//! Strict candidate RLD-WIRE-V1 codec.
//!
//! This module implements the byte baseline frozen in `spec/wire/README.md`.
//! It is versioned separately from the legacy JSON and hand-built signing
//! layouts. Runtime callers must select the version explicitly; this codec has
//! no permissive fallback.

use std::fmt;

use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

pub const MAGIC: &[u8; 4] = b"RLDW";
pub const WIRE_VERSION: u16 = 1;
pub const SIGNATURE_PREFIX: &[u8] = b"RLD-SIGNATURE-PREIMAGE-V1\0";
pub const SUBJECT_PREFIX: &[u8] = b"RLD-SUBJECT-HASH-PREIMAGE-V1\0";

const K_TEXT: u8 = 0x01;
const K_U8: u8 = 0x02;
const K_U16: u8 = 0x03;
const K_U64: u8 = 0x04;
const K_U128: u8 = 0x05;
const K_HASH32: u8 = 0x06;
const K_BYTES32: u8 = 0x07;
const K_HASH32_LIST: u8 = 0x08;
const K_BYTES: u8 = 0x09;
const K_BYTES32_LIST: u8 = 0x0a;

pub const MAX_COMMAND_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_CONSENSUS_CERTIFICATE_MEMBERS: usize = 4096;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct WireError {
    pub code: &'static str,
    pub message: String,
}

impl WireError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

type WireResult<T> = Result<T, WireError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WirePurpose {
    Signature,
    Subject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireSchema {
    Amount,
    LogicalHeight,
    ZoneDomainContext,
    PaymentRequest,
    UniversalPaymentIntent,
    ConsensusProposal,
    ConsensusVote,
    ConsensusCommit,
    ConsensusValidatorSet,
    TimeoutVote,
    TimeoutCertificate,
    PrepareVote,
    PrepareCertificate,
    CommitVote,
    CommitCertificate,
    ViewChangeProposal,
    ValueRiskPolicyUpdate,
    CommandCommitment,
}

impl WireSchema {
    pub const fn id(self) -> u16 {
        match self {
            Self::Amount => 0x0001,
            Self::LogicalHeight => 0x0002,
            Self::ZoneDomainContext => 0x0100,
            Self::PaymentRequest => 0x0201,
            Self::UniversalPaymentIntent => 0x0202,
            Self::ConsensusProposal => 0x0301,
            Self::ConsensusVote => 0x0302,
            Self::ConsensusCommit => 0x0303,
            Self::ConsensusValidatorSet => 0x030f,
            Self::TimeoutVote => 0x0310,
            Self::TimeoutCertificate => 0x0311,
            Self::PrepareVote => 0x0312,
            Self::PrepareCertificate => 0x0313,
            Self::CommitVote => 0x0314,
            Self::CommitCertificate => 0x0315,
            Self::ViewChangeProposal => 0x0316,
            Self::ValueRiskPolicyUpdate => 0x0401,
            Self::CommandCommitment => 0x0500,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Amount => "Amount",
            Self::LogicalHeight => "LogicalHeight",
            Self::ZoneDomainContext => "ZoneDomainContext",
            Self::PaymentRequest => "PaymentRequest",
            Self::UniversalPaymentIntent => "UniversalPaymentIntent",
            Self::ConsensusProposal => "ConsensusProposal",
            Self::ConsensusVote => "ConsensusVote",
            Self::ConsensusCommit => "ConsensusCommit",
            Self::ConsensusValidatorSet => "ConsensusValidatorSet",
            Self::TimeoutVote => "TimeoutVote",
            Self::TimeoutCertificate => "TimeoutCertificate",
            Self::PrepareVote => "PrepareVote",
            Self::PrepareCertificate => "PrepareCertificate",
            Self::CommitVote => "CommitVote",
            Self::CommitCertificate => "CommitCertificate",
            Self::ViewChangeProposal => "ViewChangeProposal",
            Self::ValueRiskPolicyUpdate => "ValueRiskPolicyUpdate",
            Self::CommandCommitment => "CommandCommitment",
        }
    }

    pub const fn purpose(self) -> WirePurpose {
        match self {
            Self::PaymentRequest
            | Self::UniversalPaymentIntent
            | Self::ConsensusProposal
            | Self::ConsensusVote
            | Self::TimeoutVote
            | Self::PrepareVote
            | Self::CommitVote
            | Self::ViewChangeProposal => WirePurpose::Signature,
            Self::Amount
            | Self::LogicalHeight
            | Self::ZoneDomainContext
            | Self::ConsensusCommit
            | Self::ConsensusValidatorSet
            | Self::TimeoutCertificate
            | Self::PrepareCertificate
            | Self::CommitCertificate
            | Self::ValueRiskPolicyUpdate
            | Self::CommandCommitment => WirePurpose::Subject,
        }
    }

    fn fields(self) -> &'static [FieldSpec] {
        match self {
            Self::Amount => AMOUNT_FIELDS,
            Self::LogicalHeight => LOGICAL_HEIGHT_FIELDS,
            Self::ZoneDomainContext => ZONE_DOMAIN_FIELDS,
            Self::PaymentRequest => PAYMENT_REQUEST_FIELDS,
            Self::UniversalPaymentIntent => PAYMENT_INTENT_FIELDS,
            Self::ConsensusProposal => PROPOSAL_FIELDS,
            Self::ConsensusVote => VOTE_FIELDS,
            Self::ConsensusCommit => COMMIT_FIELDS,
            Self::ConsensusValidatorSet => CONSENSUS_VALIDATOR_SET_FIELDS,
            Self::TimeoutVote => TIMEOUT_VOTE_FIELDS,
            Self::TimeoutCertificate => TIMEOUT_CERTIFICATE_FIELDS,
            Self::PrepareVote => PREPARE_VOTE_FIELDS,
            Self::PrepareCertificate => PREPARE_CERTIFICATE_FIELDS,
            Self::CommitVote => COMMIT_VOTE_FIELDS,
            Self::CommitCertificate => COMMIT_CERTIFICATE_FIELDS,
            Self::ViewChangeProposal => VIEW_CHANGE_PROPOSAL_FIELDS,
            Self::ValueRiskPolicyUpdate => VALUE_RISK_FIELDS,
            Self::CommandCommitment => COMMAND_COMMITMENT_FIELDS,
        }
    }
}

impl TryFrom<&str> for WireSchema {
    type Error = WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Amount" => Ok(Self::Amount),
            "LogicalHeight" => Ok(Self::LogicalHeight),
            "ZoneDomainContext" => Ok(Self::ZoneDomainContext),
            "PaymentRequest" => Ok(Self::PaymentRequest),
            "UniversalPaymentIntent" => Ok(Self::UniversalPaymentIntent),
            "ConsensusProposal" => Ok(Self::ConsensusProposal),
            "ConsensusVote" => Ok(Self::ConsensusVote),
            "ConsensusCommit" => Ok(Self::ConsensusCommit),
            "ConsensusValidatorSet" => Ok(Self::ConsensusValidatorSet),
            "TimeoutVote" => Ok(Self::TimeoutVote),
            "TimeoutCertificate" => Ok(Self::TimeoutCertificate),
            "PrepareVote" => Ok(Self::PrepareVote),
            "PrepareCertificate" => Ok(Self::PrepareCertificate),
            "CommitVote" => Ok(Self::CommitVote),
            "CommitCertificate" => Ok(Self::CommitCertificate),
            "ViewChangeProposal" => Ok(Self::ViewChangeProposal),
            "ValueRiskPolicyUpdate" => Ok(Self::ValueRiskPolicyUpdate),
            "CommandCommitment" => Ok(Self::CommandCommitment),
            _ => Err(WireError::new(
                "unknown_schema",
                format!("unknown schema {value:?}"),
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum TextClass {
    Plain,
    Network,
    Zone,
    Identifier,
    Recipient,
}

#[derive(Clone, Copy)]
struct FieldSpec {
    id: u16,
    name: &'static str,
    kind: u8,
    required: bool,
    max_bytes: Option<usize>,
    text_class: TextClass,
}

const fn field(id: u16, name: &'static str, kind: u8) -> FieldSpec {
    FieldSpec {
        id,
        name,
        kind,
        required: true,
        max_bytes: None,
        text_class: TextClass::Plain,
    }
}

const fn text(id: u16, name: &'static str, max_bytes: usize, class: TextClass) -> FieldSpec {
    FieldSpec {
        id,
        name,
        kind: K_TEXT,
        required: true,
        max_bytes: Some(max_bytes),
        text_class: class,
    }
}

const fn optional_text(
    id: u16,
    name: &'static str,
    max_bytes: usize,
    class: TextClass,
) -> FieldSpec {
    FieldSpec {
        required: false,
        ..text(id, name, max_bytes, class)
    }
}

const AMOUNT_FIELDS: &[FieldSpec] = &[field(1, "value", K_U128)];
const LOGICAL_HEIGHT_FIELDS: &[FieldSpec] = &[field(1, "value", K_U128)];
const ZONE_DOMAIN_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
];
const PAYMENT_REQUEST_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "request_id", 128, TextClass::Identifier),
    text(3, "recipient", 160, TextClass::Recipient),
    field(4, "recipient_public_key", K_BYTES32),
    text(5, "destination_zone", 64, TextClass::Zone),
    field(6, "currency_genesis_root", K_HASH32),
    field(7, "protocol_era", K_U64),
    field(8, "crypto_era", K_U64),
    field(9, "amount", K_U128),
    text(10, "memo", 512, TextClass::Plain),
    field(11, "expires_at_height", K_U128),
    field(12, "nonce", K_U64),
];
const PAYMENT_INTENT_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "payment_id", 128, TextClass::Identifier),
    text(3, "source_zone", 64, TextClass::Zone),
    text(4, "destination_zone", 64, TextClass::Zone),
    field(5, "currency_genesis_root", K_HASH32),
    field(6, "protocol_era", K_U64),
    field(7, "crypto_era", K_U64),
    field(8, "pricing_epoch", K_U64),
    field(9, "sender_public_key", K_BYTES32),
    text(10, "recipient", 160, TextClass::Recipient),
    text(11, "coin_id", 128, TextClass::Identifier),
    field(12, "amount", K_U128),
    field(13, "max_fee", K_U128),
    field(14, "nonce", K_U64),
    optional_text(15, "payment_request_id", 128, TextClass::Identifier),
    FieldSpec {
        required: false,
        ..field(16, "payment_request_hash", K_HASH32)
    },
    optional_text(17, "route_quote_id", 128, TextClass::Identifier),
];
const PROPOSAL_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "proposal_id", 128, TextClass::Identifier),
    text(3, "zone_id", 64, TextClass::Zone),
    field(4, "currency_genesis_root", K_HASH32),
    field(5, "protocol_era", K_U64),
    field(6, "crypto_era", K_U64),
    field(7, "parent_height", K_U128),
    field(8, "parent_state_root", K_HASH32),
    field(9, "round", K_U64),
    field(10, "proposer_public_key", K_BYTES32),
    field(11, "command_hash", K_HASH32),
    field(12, "expected_height", K_U128),
    field(13, "expected_state_root", K_HASH32),
];
const VOTE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "proposal_id", 128, TextClass::Identifier),
    field(3, "proposal_hash", K_HASH32),
    text(4, "zone_id", 64, TextClass::Zone),
    field(5, "currency_genesis_root", K_HASH32),
    field(6, "protocol_era", K_U64),
    field(7, "crypto_era", K_U64),
    field(8, "parent_height", K_U128),
    field(9, "parent_state_root", K_HASH32),
    field(10, "round", K_U64),
    field(11, "expected_state_root", K_HASH32),
    field(12, "voter_public_key", K_BYTES32),
];
const COMMIT_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "proposal_hash", K_HASH32),
    field(7, "expected_height", K_U128),
    field(8, "expected_state_root", K_HASH32),
    field(9, "vote_hashes", K_HASH32_LIST),
];
const CONSENSUS_VALIDATOR_SET_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_public_keys", K_BYTES32_LIST),
];
const TIMEOUT_VOTE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "timed_out_round", K_U64),
    FieldSpec {
        required: false,
        ..field(13, "high_prepare_qc_round", K_U64)
    },
    FieldSpec {
        required: false,
        ..field(14, "high_prepare_qc_block_id", K_HASH32)
    },
    FieldSpec {
        required: false,
        ..field(15, "high_prepare_qc_hash", K_HASH32)
    },
    field(16, "voter_public_key", K_BYTES32),
];
const TIMEOUT_CERTIFICATE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "timed_out_round", K_U64),
    FieldSpec {
        required: false,
        ..field(13, "selected_high_prepare_qc_round", K_U64)
    },
    FieldSpec {
        required: false,
        ..field(14, "selected_high_prepare_qc_block_id", K_HASH32)
    },
    FieldSpec {
        required: false,
        ..field(15, "selected_high_prepare_qc_hash", K_HASH32)
    },
    field(16, "timeout_vote_hashes", K_HASH32_LIST),
];
const PREPARE_VOTE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "round", K_U64),
    field(13, "block_id", K_HASH32),
    field(14, "proposal_hash", K_HASH32),
    field(15, "command_hash", K_HASH32),
    field(16, "expected_height", K_U128),
    field(17, "expected_state_root", K_HASH32),
    field(18, "voter_public_key", K_BYTES32),
];
const PREPARE_CERTIFICATE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "round", K_U64),
    field(13, "block_id", K_HASH32),
    field(14, "proposal_hash", K_HASH32),
    field(15, "command_hash", K_HASH32),
    field(16, "expected_height", K_U128),
    field(17, "expected_state_root", K_HASH32),
    field(18, "prepare_vote_hashes", K_HASH32_LIST),
];
const COMMIT_VOTE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "round", K_U64),
    field(13, "block_id", K_HASH32),
    field(14, "proposal_hash", K_HASH32),
    field(15, "command_hash", K_HASH32),
    field(16, "expected_height", K_U128),
    field(17, "expected_state_root", K_HASH32),
    field(18, "prepare_certificate_hash", K_HASH32),
    field(19, "voter_public_key", K_BYTES32),
];
const COMMIT_CERTIFICATE_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "round", K_U64),
    field(13, "block_id", K_HASH32),
    field(14, "proposal_hash", K_HASH32),
    field(15, "command_hash", K_HASH32),
    field(16, "expected_height", K_U128),
    field(17, "expected_state_root", K_HASH32),
    field(18, "prepare_certificate_hash", K_HASH32),
    field(19, "commit_vote_hashes", K_HASH32_LIST),
];
const VIEW_CHANGE_PROPOSAL_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "zone_id", 64, TextClass::Zone),
    field(3, "currency_genesis_root", K_HASH32),
    field(4, "protocol_era", K_U64),
    field(5, "crypto_era", K_U64),
    field(6, "consensus_protocol_version", K_U64),
    field(7, "validator_set_epoch", K_U64),
    field(8, "validator_set_commitment", K_HASH32),
    field(9, "parent_height", K_U128),
    field(10, "parent_block_id", K_HASH32),
    field(11, "parent_state_root", K_HASH32),
    field(12, "round", K_U64),
    field(13, "proposer_public_key", K_BYTES32),
    field(14, "block_id", K_HASH32),
    field(15, "command_hash", K_HASH32),
    field(16, "expected_height", K_U128),
    field(17, "expected_state_root", K_HASH32),
    field(18, "timeout_certificate_hash", K_HASH32),
    FieldSpec {
        required: false,
        ..field(19, "high_prepare_qc_round", K_U64)
    },
    FieldSpec {
        required: false,
        ..field(20, "high_prepare_qc_block_id", K_HASH32)
    },
    FieldSpec {
        required: false,
        ..field(21, "high_prepare_qc_hash", K_HASH32)
    },
];
const VALUE_RISK_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    text(2, "update_id", 128, TextClass::Identifier),
    text(3, "zone_id", 64, TextClass::Zone),
    field(4, "currency_genesis_root", K_HASH32),
    field(5, "protocol_era", K_U64),
    field(6, "crypto_era", K_U64),
    field(7, "policy_version", K_U16),
    field(8, "previous_policy_sequence", K_U64),
    field(9, "from_cap", K_U8),
    field(10, "to_cap", K_U8),
    field(11, "max_single_transfer", K_U128),
    field(12, "max_local_value_total", K_U128),
    field(13, "max_cross_zone_exposure", K_U128),
    field(14, "max_dsc_exposure", K_U128),
    field(15, "safety_case_hash", K_HASH32),
    field(16, "safety_case_valid_until_height", K_U128),
    field(17, "proposed_height", K_U128),
    field(18, "activate_after_height", K_U128),
    field(19, "expires_at_height", K_U128),
    field(20, "nonce", K_U64),
];
const COMMAND_COMMITMENT_FIELDS: &[FieldSpec] = &[
    text(1, "network_domain", 64, TextClass::Network),
    field(2, "consensus_tag", K_U16),
    FieldSpec {
        required: false,
        ..field(3, "production_tag", K_U16)
    },
    FieldSpec {
        max_bytes: Some(MAX_COMMAND_PAYLOAD_BYTES),
        ..field(4, "payload", K_BYTES)
    },
];

/// Encodes the typed command envelope without routing consensus bytes through
/// a JSON value model. JSON is only an interchange projection for the generic
/// vector verifier; runtime command commitments use this entry point.
pub fn encode_command_commitment(
    network_domain: &str,
    consensus_tag: u16,
    production_tag: Option<u16>,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    validate_text(COMMAND_COMMITMENT_FIELDS[0], network_domain)?;
    validate_command_envelope(consensus_tag, production_tag, payload.len())?;

    encode_command_commitment_fields(network_domain, consensus_tag, production_tag, payload)
}

/// Produces frozen bytes for a reserved top-level command tag. This helper is
/// retained for pre-adoption vector compatibility; a tag becomes decodable
/// only when `validate_command_envelope` explicitly admits it.
pub(crate) fn encode_reserved_command_commitment_candidate(
    network_domain: &str,
    consensus_tag: u16,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    validate_text(COMMAND_COMMITMENT_FIELDS[0], network_domain)?;
    if !(26..=35).contains(&consensus_tag) && !matches!(consensus_tag, 37 | 38) {
        return Err(WireError::new(
            "not_reserved_command_tag",
            "codec-only command tag must be in the reserved 26..35 or 37..38 ranges",
        ));
    }
    if payload.is_empty() || payload.len() > MAX_COMMAND_PAYLOAD_BYTES {
        return Err(WireError::new(
            "invalid_command_payload",
            "reserved codec-only command payload must be nonempty and at most 1 MiB",
        ));
    }
    encode_command_commitment_fields(network_domain, consensus_tag, None, payload)
}

fn encode_command_commitment_fields(
    network_domain: &str,
    consensus_tag: u16,
    production_tag: Option<u16>,
    payload: &[u8],
) -> WireResult<Vec<u8>> {
    let count = if production_tag.is_some() { 4u16 } else { 3u16 };
    let capacity = 10usize
        .checked_add(7 + network_domain.len())
        .and_then(|value| value.checked_add(7 + 2))
        .and_then(|value| value.checked_add(production_tag.map_or(0, |_| 7 + 2)))
        .and_then(|value| value.checked_add(7 + payload.len()))
        .ok_or_else(|| WireError::new("integer_overflow", "command envelope size overflow"))?;
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    wire.extend_from_slice(&WireSchema::CommandCommitment.id().to_be_bytes());
    wire.extend_from_slice(&count.to_be_bytes());
    push_raw_field(&mut wire, 1, K_TEXT, network_domain.as_bytes())?;
    push_raw_field(&mut wire, 2, K_U16, &consensus_tag.to_be_bytes())?;
    if let Some(tag) = production_tag {
        push_raw_field(&mut wire, 3, K_U16, &tag.to_be_bytes())?;
    }
    push_raw_field(&mut wire, 4, K_BYTES, payload)?;
    Ok(wire)
}

fn push_raw_field(wire: &mut Vec<u8>, id: u16, kind: u8, payload: &[u8]) -> WireResult<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| WireError::new("field_too_long", "command envelope field exceeds u32"))?;
    wire.extend_from_slice(&id.to_be_bytes());
    wire.push(kind);
    wire.extend_from_slice(&length.to_be_bytes());
    wire.extend_from_slice(payload);
    Ok(())
}

fn validate_command_envelope(
    consensus_tag: u16,
    production_tag: Option<u16>,
    payload_len: usize,
) -> WireResult<()> {
    if !(1..=25).contains(&consensus_tag)
        && consensus_tag != 28
        && consensus_tag != 36
        && consensus_tag != 37
        && consensus_tag != 38
    {
        return Err(WireError::new(
            "unknown_command_tag",
            "unknown consensus command tag",
        ));
    }
    if (consensus_tag == 7) != production_tag.is_some() {
        return Err(WireError::new(
            "invalid_command_envelope",
            "production tag presence does not match consensus tag",
        ));
    }
    if production_tag.is_some_and(|tag| !(1..=30).contains(&tag)) {
        return Err(WireError::new(
            "unknown_production_tag",
            "unknown production command tag",
        ));
    }
    if (consensus_tag == 6) != (payload_len == 0) {
        return Err(WireError::new(
            "invalid_command_payload",
            "only activation command has an empty payload",
        ));
    }
    if payload_len > MAX_COMMAND_PAYLOAD_BYTES {
        return Err(WireError::new(
            "field_too_long",
            "command payload exceeds 1 MiB",
        ));
    }
    Ok(())
}

pub fn encode_source(schema: WireSchema, source: &Map<String, Value>) -> WireResult<Vec<u8>> {
    let fields = schema.fields();
    for key in source.keys() {
        if !fields.iter().any(|field| field.name == key) {
            return Err(WireError::new(
                "unknown_field",
                format!("unknown field {key:?}"),
            ));
        }
    }
    let missing = fields
        .iter()
        .filter(|field| field.required && !source.contains_key(field.name))
        .map(|field| field.name)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(WireError::new(
            "missing_field",
            format!("missing field(s): {}", missing.join(", ")),
        ));
    }

    let mut entries = Vec::new();
    for field in fields {
        let Some(value) = source.get(field.name) else {
            continue;
        };
        let payload = encode_value(*field, value)?;
        entries.extend_from_slice(&field.id.to_be_bytes());
        entries.push(field.kind);
        let length = u32::try_from(payload.len())
            .map_err(|_| WireError::new("field_too_long", field.name))?;
        entries.extend_from_slice(&length.to_be_bytes());
        entries.extend_from_slice(&payload);
    }
    validate_object(schema, source)?;
    let count = u16::try_from(source.len())
        .map_err(|_| WireError::new("field_too_long", "too many fields"))?;
    let mut wire = Vec::with_capacity(10 + entries.len());
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    wire.extend_from_slice(&schema.id().to_be_bytes());
    wire.extend_from_slice(&count.to_be_bytes());
    wire.extend_from_slice(&entries);
    Ok(wire)
}

pub fn decode_wire(schema: WireSchema, wire: &[u8]) -> WireResult<Map<String, Value>> {
    if wire.len() < 10 {
        return Err(WireError::new("truncated", "wire header is incomplete"));
    }
    if &wire[..4] != MAGIC {
        return Err(WireError::new("bad_magic", "wire magic mismatch"));
    }
    let version = u16::from_be_bytes([wire[4], wire[5]]);
    if version != WIRE_VERSION {
        return Err(WireError::new(
            "unsupported_version",
            format!("unsupported wire version {version}"),
        ));
    }
    let encoded_schema = u16::from_be_bytes([wire[6], wire[7]]);
    if encoded_schema != schema.id() {
        return Err(WireError::new(
            "signature_domain_substitution",
            "schema domain does not match object",
        ));
    }
    let count = u16::from_be_bytes([wire[8], wire[9]]);
    let mut offset = 10usize;
    let mut previous_id = None;
    let mut source = Map::new();
    for _ in 0..count {
        let header = wire
            .get(offset..offset.saturating_add(7))
            .ok_or_else(|| WireError::new("truncated", "field header is incomplete"))?;
        let field_id = u16::from_be_bytes([header[0], header[1]]);
        if previous_id == Some(field_id) {
            return Err(WireError::new(
                "duplicate_field",
                format!("duplicate field id {field_id}"),
            ));
        }
        if previous_id.is_some_and(|previous| field_id < previous) {
            return Err(WireError::new(
                "field_order",
                "fields are not strictly increasing",
            ));
        }
        previous_id = Some(field_id);
        let kind = header[2];
        let length = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
        offset += 7;
        let field = schema
            .fields()
            .iter()
            .find(|field| field.id == field_id)
            .copied()
            .ok_or_else(|| {
                WireError::new(
                    "unknown_field",
                    format!("unknown critical field id {field_id}"),
                )
            })?;
        if kind != field.kind {
            return Err(WireError::new(
                "wrong_wire_type",
                format!("wrong type for field {}", field.name),
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| WireError::new("integer_overflow", "field length overflow"))?;
        let payload = wire.get(offset..end).ok_or_else(|| {
            WireError::new("truncated", format!("{} payload is incomplete", field.name))
        })?;
        offset = end;
        source.insert(field.name.to_owned(), decode_value(field, payload)?);
    }
    if offset != wire.len() {
        return Err(WireError::new(
            "trailing_data",
            "bytes remain after declared field count",
        ));
    }
    let missing = schema
        .fields()
        .iter()
        .filter(|field| field.required && !source.contains_key(field.name))
        .map(|field| field.name)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(WireError::new(
            "missing_field",
            format!("missing field(s): {}", missing.join(", ")),
        ));
    }
    validate_object(schema, &source)?;
    if encode_source(schema, &source)? != wire {
        return Err(WireError::new(
            "noncanonical_wire",
            "decoded value does not round-trip byte-for-byte",
        ));
    }
    Ok(source)
}

pub fn preimage(schema: WireSchema, wire: &[u8]) -> Vec<u8> {
    let prefix = match schema.purpose() {
        WirePurpose::Signature => SIGNATURE_PREFIX,
        WirePurpose::Subject => SUBJECT_PREFIX,
    };
    let mut bytes = Vec::with_capacity(prefix.len() + wire.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(wire);
    bytes
}

pub fn digest_hex(schema: WireSchema, wire: &[u8]) -> String {
    hex::encode(Sha256::digest(preimage(schema, wire)))
}

pub fn validate_context(
    schema: WireSchema,
    source: &Map<String, Value>,
    context: &Map<String, Value>,
) -> WireResult<()> {
    let zone_field = match schema {
        WireSchema::ZoneDomainContext
        | WireSchema::ConsensusProposal
        | WireSchema::ConsensusVote
        | WireSchema::ConsensusCommit
        | WireSchema::ConsensusValidatorSet
        | WireSchema::TimeoutVote
        | WireSchema::TimeoutCertificate
        | WireSchema::PrepareVote
        | WireSchema::PrepareCertificate
        | WireSchema::CommitVote
        | WireSchema::CommitCertificate
        | WireSchema::ViewChangeProposal
        | WireSchema::ValueRiskPolicyUpdate => Some("zone_id"),
        WireSchema::PaymentRequest => Some("destination_zone"),
        WireSchema::UniversalPaymentIntent => Some("source_zone"),
        WireSchema::Amount | WireSchema::LogicalHeight | WireSchema::CommandCommitment => None,
    };
    let mut mappings = vec![
        ("expected_network_domain", "network_domain"),
        ("expected_currency_genesis_root", "currency_genesis_root"),
        ("expected_protocol_era", "protocol_era"),
        ("expected_crypto_era", "crypto_era"),
    ];
    if let Some(field) = zone_field {
        mappings.push(("expected_zone_id", field));
    }
    if schema == WireSchema::UniversalPaymentIntent {
        mappings.push(("expected_destination_zone", "destination_zone"));
    }
    if matches!(
        schema,
        WireSchema::ConsensusValidatorSet
            | WireSchema::TimeoutVote
            | WireSchema::TimeoutCertificate
            | WireSchema::PrepareVote
            | WireSchema::PrepareCertificate
            | WireSchema::CommitVote
            | WireSchema::CommitCertificate
            | WireSchema::ViewChangeProposal
    ) {
        mappings.push((
            "expected_consensus_protocol_version",
            "consensus_protocol_version",
        ));
        mappings.push(("expected_validator_set_epoch", "validator_set_epoch"));
    }
    if matches!(
        schema,
        WireSchema::TimeoutVote
            | WireSchema::TimeoutCertificate
            | WireSchema::PrepareVote
            | WireSchema::PrepareCertificate
            | WireSchema::CommitVote
            | WireSchema::CommitCertificate
            | WireSchema::ViewChangeProposal
    ) {
        mappings.push((
            "expected_validator_set_commitment",
            "validator_set_commitment",
        ));
        mappings.push(("expected_parent_height", "parent_height"));
        mappings.push(("expected_parent_block_id", "parent_block_id"));
        mappings.push(("expected_parent_state_root", "parent_state_root"));
    }
    for (expected, actual) in mappings {
        if let Some(expected_value) = context.get(expected) {
            if source.get(actual) != Some(expected_value) {
                return Err(WireError::new(
                    "context_mismatch",
                    format!("{actual} does not match verifier context"),
                ));
            }
        }
    }
    Ok(())
}

pub fn parse_strict_json_object(input: &str) -> WireResult<Map<String, Value>> {
    let value = serde_json::from_str::<StrictJsonValue>(input)
        .map_err(|error| {
            if error.to_string().contains("duplicate_json_key") {
                WireError::new("duplicate_json_key", error.to_string())
            } else {
                WireError::new("invalid_json", error.to_string())
            }
        })?
        .0;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| WireError::new("wrong_type", "JSON source must be an object"))
}

fn encode_value(field: FieldSpec, value: &Value) -> WireResult<Vec<u8>> {
    match field.kind {
        K_TEXT => {
            let value = value.as_str().ok_or_else(|| {
                WireError::new("wrong_type", format!("{} must be text", field.name))
            })?;
            validate_text(field, value)?;
            Ok(value.as_bytes().to_vec())
        }
        K_U8 => Ok(parse_uint(value, 8, field.name)?.to_be_bytes()[15..].to_vec()),
        K_U16 => Ok(parse_uint(value, 16, field.name)?.to_be_bytes()[14..].to_vec()),
        K_U64 => Ok(parse_uint(value, 64, field.name)?.to_be_bytes()[8..].to_vec()),
        K_U128 => Ok(parse_uint(value, 128, field.name)?.to_be_bytes().to_vec()),
        K_HASH32 | K_BYTES32 => Ok(parse_hex32(value, field.name)?.to_vec()),
        K_HASH32_LIST | K_BYTES32_LIST => {
            let values = value.as_array().ok_or_else(|| {
                WireError::new("wrong_type", format!("{} must be a list", field.name))
            })?;
            let count = u16::try_from(values.len()).map_err(|_| {
                WireError::new(
                    "field_too_long",
                    format!("{} has too many entries", field.name),
                )
            })?;
            let raw = values
                .iter()
                .map(|value| parse_hex32(value, field.name))
                .collect::<WireResult<Vec<_>>>()?;
            if !raw.windows(2).all(|window| window[0] < window[1]) {
                if raw.windows(2).any(|window| window[0] == window[1]) {
                    return Err(WireError::new(
                        "duplicate_list_item",
                        format!("{} contains duplicates", field.name),
                    ));
                }
                return Err(WireError::new(
                    "noncanonical_list_order",
                    format!("{} must be sorted", field.name),
                ));
            }
            let mut payload = Vec::with_capacity(2 + raw.len() * 32);
            payload.extend_from_slice(&count.to_be_bytes());
            for hash in raw {
                payload.extend_from_slice(&hash);
            }
            Ok(payload)
        }
        K_BYTES => {
            let value = value.as_str().ok_or_else(|| {
                WireError::new(
                    "noncanonical_hex",
                    format!("{} must be lowercase even-length hex", field.name),
                )
            })?;
            if value.len() % 2 != 0
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(WireError::new(
                    "noncanonical_hex",
                    format!("{} must be lowercase even-length hex", field.name),
                ));
            }
            let decoded = hex::decode(value).map_err(|_| {
                WireError::new("noncanonical_hex", format!("invalid {}", field.name))
            })?;
            if field
                .max_bytes
                .is_some_and(|maximum| decoded.len() > maximum)
            {
                return Err(WireError::new(
                    "field_too_long",
                    format!("{} exceeds its byte limit", field.name),
                ));
            }
            Ok(decoded)
        }
        _ => unreachable!("schema contains an unknown kind"),
    }
}

fn decode_value(field: FieldSpec, payload: &[u8]) -> WireResult<Value> {
    match field.kind {
        K_TEXT => {
            let value = std::str::from_utf8(payload).map_err(|_| {
                WireError::new("invalid_utf8", format!("invalid UTF-8 in {}", field.name))
            })?;
            validate_text(field, value)?;
            Ok(Value::String(value.to_owned()))
        }
        K_U8 | K_U16 | K_U64 | K_U128 => {
            let width = match field.kind {
                K_U8 => 1,
                K_U16 => 2,
                K_U64 => 8,
                K_U128 => 16,
                _ => unreachable!(),
            };
            if payload.len() != width {
                return Err(WireError::new(
                    "wrong_integer_width",
                    format!("{} must occupy {width} bytes", field.name),
                ));
            }
            let mut padded = [0u8; 16];
            padded[16 - width..].copy_from_slice(payload);
            Ok(Value::String(u128::from_be_bytes(padded).to_string()))
        }
        K_HASH32 | K_BYTES32 => {
            if payload.len() != 32 {
                return Err(WireError::new(
                    "wrong_fixed_width",
                    format!("{} must occupy 32 bytes", field.name),
                ));
            }
            Ok(Value::String(hex::encode(payload)))
        }
        K_HASH32_LIST | K_BYTES32_LIST => {
            if payload.len() < 2 {
                return Err(WireError::new(
                    "truncated",
                    format!("{} lacks its count", field.name),
                ));
            }
            let count = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
            if payload.len() != 2 + count * 32 {
                return Err(WireError::new(
                    "wrong_list_length",
                    format!("{} count/length mismatch", field.name),
                ));
            }
            let values = (0..count)
                .map(|index| Value::String(hex::encode(&payload[2 + index * 32..34 + index * 32])))
                .collect::<Vec<_>>();
            encode_value(field, &Value::Array(values.clone()))?;
            Ok(Value::Array(values))
        }
        K_BYTES => {
            if field
                .max_bytes
                .is_some_and(|maximum| payload.len() > maximum)
            {
                return Err(WireError::new(
                    "field_too_long",
                    format!("{} exceeds its byte limit", field.name),
                ));
            }
            Ok(Value::String(hex::encode(payload)))
        }
        _ => unreachable!("schema contains an unknown kind"),
    }
}

fn parse_uint(value: &Value, bits: u32, name: &str) -> WireResult<u128> {
    let value = value.as_str().ok_or_else(|| {
        WireError::new(
            "noncanonical_number",
            format!("{name} must be a canonical decimal string"),
        )
    })?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WireError::new(
            "noncanonical_number",
            format!("{name} is not canonical decimal"),
        ));
    }
    let number = value
        .parse::<u128>()
        .map_err(|_| WireError::new("integer_overflow", format!("{name} exceeds u{bits}")))?;
    if bits < 128 && number >= (1u128 << bits) {
        return Err(WireError::new(
            "integer_overflow",
            format!("{name} exceeds u{bits}"),
        ));
    }
    Ok(number)
}

fn parse_hex32(value: &Value, name: &str) -> WireResult<[u8; 32]> {
    let value = value.as_str().ok_or_else(|| {
        WireError::new(
            "noncanonical_hex",
            format!("{name} must be 32-byte lowercase hex"),
        )
    })?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WireError::new(
            "noncanonical_hex",
            format!("{name} must be 32-byte lowercase hex"),
        ));
    }
    let decoded = hex::decode(value)
        .map_err(|_| WireError::new("noncanonical_hex", format!("invalid hex in {name}")))?;
    decoded
        .try_into()
        .map_err(|_| WireError::new("noncanonical_hex", format!("wrong width for {name}")))
}

fn validate_text(field: FieldSpec, value: &str) -> WireResult<()> {
    if !value.nfc().eq(value.chars()) {
        return Err(WireError::new(
            "noncanonical_unicode",
            format!("{} must be NFC", field.name),
        ));
    }
    if value
        .chars()
        .any(|character| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f))
    {
        return Err(WireError::new(
            "forbidden_control",
            format!("{} contains a control character", field.name),
        ));
    }
    if field.max_bytes.is_some_and(|maximum| value.len() > maximum) {
        return Err(WireError::new(
            "field_too_long",
            format!("{} exceeds its byte limit", field.name),
        ));
    }
    let valid = match field.text_class {
        TextClass::Plain => true,
        TextClass::Network => matches!(value, "rldcoin:mainnet:v1" | "rldcoin:testnet:v1"),
        TextClass::Zone => valid_zone(value),
        TextClass::Identifier => valid_identifier(value),
        TextClass::Recipient => valid_recipient(value),
    };
    if !valid {
        let code = match field.text_class {
            TextClass::Network => "invalid_network_domain",
            TextClass::Zone => "invalid_zone_id",
            TextClass::Identifier => "invalid_identifier",
            TextClass::Recipient => "invalid_recipient",
            TextClass::Plain => unreachable!(),
        };
        return Err(WireError::new(
            code,
            format!("invalid value in {}", field.name),
        ));
    }
    Ok(())
}

fn valid_zone(value: &str) -> bool {
    value.strip_prefix("zone-").is_some_and(|suffix| {
        suffix.len() == 20
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_recipient(value: &str) -> bool {
    let mut pieces = value.split(':');
    matches!(pieces.next(), Some("rld"))
        && pieces.next().is_some_and(valid_zone)
        && pieces.next().is_some_and(|key| {
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        && pieces.next().is_none()
}

fn source_str<'a>(source: &'a Map<String, Value>, name: &str) -> WireResult<&'a str> {
    source
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| WireError::new("wrong_type", format!("{name} must be text")))
}

fn source_uint(source: &Map<String, Value>, name: &str, bits: u32) -> WireResult<u128> {
    parse_uint(
        source
            .get(name)
            .ok_or_else(|| WireError::new("missing_field", name))?,
        bits,
        name,
    )
}

fn validate_successor(source: &Map<String, Value>) -> WireResult<()> {
    let parent = source_uint(source, "parent_height", 128)?;
    let expected = source_uint(source, "expected_height", 128)?;
    if parent == u128::MAX || expected != parent + 1 {
        return Err(WireError::new(
            "invalid_height_successor",
            "expected height must equal parent plus one",
        ));
    }
    Ok(())
}

fn validate_optional_group(source: &Map<String, Value>, names: &[&str]) -> WireResult<bool> {
    let present = names
        .iter()
        .filter(|name| source.contains_key(**name))
        .count();
    if present != 0 && present != names.len() {
        return Err(WireError::new(
            "incomplete_optional_binding",
            format!("{} must appear together", names.join(", ")),
        ));
    }
    Ok(present == names.len())
}

fn validate_consensus_member_list(source: &Map<String, Value>, name: &str) -> WireResult<()> {
    let values = source
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| WireError::new("wrong_type", format!("{name} must be a list")))?;
    if values.is_empty() {
        return Err(WireError::new(
            "empty_certificate_members",
            format!("{name} must not be empty"),
        ));
    }
    if values.len() > MAX_CONSENSUS_CERTIFICATE_MEMBERS {
        return Err(WireError::new(
            "field_too_long",
            format!("{name} exceeds the codec member cap"),
        ));
    }
    Ok(())
}

fn validate_new_consensus_context(source: &Map<String, Value>) -> WireResult<()> {
    if source_uint(source, "consensus_protocol_version", 64)? == 0 {
        return Err(WireError::new(
            "invalid_consensus_protocol_version",
            "consensus protocol version must be non-zero",
        ));
    }
    Ok(())
}

fn validate_object(schema: WireSchema, source: &Map<String, Value>) -> WireResult<()> {
    match schema {
        WireSchema::PaymentRequest => {
            let expected = format!(
                "rld:{}:{}",
                source_str(source, "destination_zone")?,
                source_str(source, "recipient_public_key")?
            );
            if source_str(source, "recipient")? != expected {
                return Err(WireError::new(
                    "recipient_scope_mismatch",
                    "recipient does not match destination/key",
                ));
            }
            if source_uint(source, "amount", 128)? == 0 {
                return Err(WireError::new(
                    "zero_amount",
                    "payment request amount must be non-zero",
                ));
            }
        }
        WireSchema::UniversalPaymentIntent => {
            let recipient = source_str(source, "recipient")?;
            let recipient_zone = recipient
                .split(':')
                .nth(1)
                .ok_or_else(|| WireError::new("invalid_recipient", "recipient lacks Zone"))?;
            if recipient_zone != source_str(source, "destination_zone")? {
                return Err(WireError::new(
                    "recipient_scope_mismatch",
                    "recipient Zone is not destination Zone",
                ));
            }
            if source.contains_key("payment_request_id")
                != source.contains_key("payment_request_hash")
            {
                return Err(WireError::new(
                    "incomplete_optional_binding",
                    "request id/hash must appear together",
                ));
            }
            if source_uint(source, "amount", 128)? == 0 {
                return Err(WireError::new(
                    "zero_amount",
                    "payment amount must be non-zero",
                ));
            }
        }
        WireSchema::ConsensusProposal => {
            validate_successor(source)?;
        }
        WireSchema::ConsensusValidatorSet => {
            validate_new_consensus_context(source)?;
            validate_consensus_member_list(source, "validator_public_keys")?;
        }
        WireSchema::TimeoutVote => {
            validate_new_consensus_context(source)?;
            let has_high_qc = validate_optional_group(
                source,
                &[
                    "high_prepare_qc_round",
                    "high_prepare_qc_block_id",
                    "high_prepare_qc_hash",
                ],
            )?;
            let timed_out_round = source_uint(source, "timed_out_round", 64)?;
            if timed_out_round == u64::MAX.into() {
                return Err(WireError::new(
                    "round_overflow",
                    "timed out round has no successor",
                ));
            }
            if has_high_qc && source_uint(source, "high_prepare_qc_round", 64)? > timed_out_round {
                return Err(WireError::new(
                    "future_high_qc",
                    "reported HighQC cannot be newer than the timed out round",
                ));
            }
        }
        WireSchema::TimeoutCertificate => {
            validate_new_consensus_context(source)?;
            let has_high_qc = validate_optional_group(
                source,
                &[
                    "selected_high_prepare_qc_round",
                    "selected_high_prepare_qc_block_id",
                    "selected_high_prepare_qc_hash",
                ],
            )?;
            let timed_out_round = source_uint(source, "timed_out_round", 64)?;
            if timed_out_round == u64::MAX.into() {
                return Err(WireError::new(
                    "round_overflow",
                    "timed out round has no successor",
                ));
            }
            if has_high_qc
                && source_uint(source, "selected_high_prepare_qc_round", 64)? > timed_out_round
            {
                return Err(WireError::new(
                    "future_high_qc",
                    "selected HighQC cannot be newer than the timed out round",
                ));
            }
            validate_consensus_member_list(source, "timeout_vote_hashes")?;
        }
        WireSchema::PrepareVote => {
            validate_new_consensus_context(source)?;
            validate_successor(source)?;
        }
        WireSchema::PrepareCertificate => {
            validate_new_consensus_context(source)?;
            validate_successor(source)?;
            validate_consensus_member_list(source, "prepare_vote_hashes")?;
        }
        WireSchema::CommitVote => {
            validate_new_consensus_context(source)?;
            validate_successor(source)?;
        }
        WireSchema::CommitCertificate => {
            validate_new_consensus_context(source)?;
            validate_successor(source)?;
            validate_consensus_member_list(source, "commit_vote_hashes")?;
        }
        WireSchema::ViewChangeProposal => {
            validate_new_consensus_context(source)?;
            validate_successor(source)?;
            let round = source_uint(source, "round", 64)?;
            if round == 0 {
                return Err(WireError::new(
                    "invalid_view_change_round",
                    "view-change proposal round must be non-zero",
                ));
            }
            let has_high_qc = validate_optional_group(
                source,
                &[
                    "high_prepare_qc_round",
                    "high_prepare_qc_block_id",
                    "high_prepare_qc_hash",
                ],
            )?;
            if has_high_qc && source_uint(source, "high_prepare_qc_round", 64)? >= round {
                return Err(WireError::new(
                    "future_high_qc",
                    "proposal HighQC must precede the target round",
                ));
            }
        }
        WireSchema::ValueRiskPolicyUpdate => {
            if source_uint(source, "from_cap", 8)? > 3 || source_uint(source, "to_cap", 8)? > 3 {
                return Err(WireError::new(
                    "invalid_value_cap",
                    "value cap code must be 0..3",
                ));
            }
            let proposed = source_uint(source, "proposed_height", 128)?;
            let activate = source_uint(source, "activate_after_height", 128)?;
            let expires = source_uint(source, "expires_at_height", 128)?;
            let valid_until = source_uint(source, "safety_case_valid_until_height", 128)?;
            if !(proposed < activate && activate <= expires && valid_until >= activate) {
                return Err(WireError::new(
                    "invalid_policy_height_window",
                    "invalid policy activation window",
                ));
            }
        }
        WireSchema::CommandCommitment => {
            let consensus_tag = u16::try_from(source_uint(source, "consensus_tag", 16)?)
                .map_err(|_| WireError::new("integer_overflow", "consensus tag exceeds u16"))?;
            let production_tag = source
                .get("production_tag")
                .map(|tag| parse_uint(tag, 16, "production_tag"))
                .transpose()?
                .map(u16::try_from)
                .transpose()
                .map_err(|_| WireError::new("integer_overflow", "production tag exceeds u16"))?;
            let payload_len = source_str(source, "payload")?.len() / 2;
            validate_command_envelope(consensus_tag, production_tag, payload_len)?;
        }
        WireSchema::Amount
        | WireSchema::LogicalHeight
        | WireSchema::ZoneDomainContext
        | WireSchema::ConsensusVote
        | WireSchema::ConsensusCommit => {}
    }
    Ok(())
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate_json_key: {key}")));
            }
            let value = object.next_value_seed(StrictValueSeed)?;
            values.insert(key, value.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = StrictJsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonValue::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deterministic_round_zero_leader, generate_identity, sign_bytes, Amount, ConsensusCommand,
        ConsensusCommit, ConsensusProposal, ConsensusVote, Ledger, LedgerError, QuorumCertificate,
        ValueCap, ValueRiskLimits, ValueRiskPolicyUpdate, RLDCOIN_MAINNET_DOMAIN,
        RLDCOIN_TESTNET_DOMAIN,
    };
    use serde_json::json;

    const VECTORS: &[u8] = include_bytes!("../../../vectors/wire-v1/vectors.json");
    const VECTOR_SHA256: &str = include_str!("../../../vectors/wire-v1/vectors.json.sha256");
    const CONSENSUS_ROUND_VECTORS: &[u8] =
        include_bytes!("../../../vectors/wire-v1/consensus-rounds.json");
    const CONSENSUS_ROUND_VECTOR_SHA256: &str =
        include_str!("../../../vectors/wire-v1/consensus-rounds.json.sha256");
    const CONSENSUS_CERTIFICATE_VECTORS: &[u8] =
        include_bytes!("../../../vectors/wire-v1/consensus-certificates.json");
    const CONSENSUS_CERTIFICATE_VECTOR_SHA256: &str =
        include_str!("../../../vectors/wire-v1/consensus-certificates.json.sha256");

    #[test]
    fn all_frozen_content_addressed_vectors_match() {
        let expected_sidecar = format!("{}  vectors.json\n", hex::encode(Sha256::digest(VECTORS)));
        assert_eq!(VECTOR_SHA256, expected_sidecar);

        let bundle = serde_json::from_slice::<StrictJsonValue>(VECTORS)
            .unwrap()
            .0;
        let payload = bundle["payload"].as_object().unwrap();
        assert_eq!(
            bundle["payload_sha256"].as_str().unwrap(),
            hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap()))
        );
        let cases = payload["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 31);
        for case in cases {
            verify_vector_case(case).unwrap_or_else(|error| {
                panic!("{} failed: {error}", case["name"].as_str().unwrap())
            });
        }
    }

    #[test]
    fn frozen_consensus_round_codec_vectors_match() {
        let expected_sidecar = format!(
            "{}  consensus-rounds.json\n",
            hex::encode(Sha256::digest(CONSENSUS_ROUND_VECTORS))
        );
        assert_eq!(CONSENSUS_ROUND_VECTOR_SHA256, expected_sidecar);

        let bundle = serde_json::from_slice::<StrictJsonValue>(CONSENSUS_ROUND_VECTORS)
            .unwrap()
            .0;
        let payload = bundle["payload"].as_object().unwrap();
        assert_eq!(
            bundle["payload_sha256"].as_str().unwrap(),
            hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap()))
        );
        assert_eq!(payload["runtime_adoption_claim"], Value::Bool(false));
        assert_eq!(payload["signature_verification_claim"], Value::Bool(false));
        assert_eq!(payload["quorum_verification_claim"], Value::Bool(false));
        assert_eq!(payload["state_machine_claim"], Value::Bool(false));
        let cases = payload["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 43);
        for case in cases {
            verify_vector_case(case).unwrap_or_else(|error| {
                panic!("{} failed: {error}", case["name"].as_str().unwrap())
            });
        }
    }

    #[test]
    fn frozen_consensus_certificate_evidence_matches_strict_rust_crypto() {
        use ed25519_dalek::SigningKey;
        use std::collections::{HashMap, HashSet};

        let expected_sidecar = format!(
            "{}  consensus-certificates.json\n",
            hex::encode(Sha256::digest(CONSENSUS_CERTIFICATE_VECTORS))
        );
        assert_eq!(CONSENSUS_CERTIFICATE_VECTOR_SHA256, expected_sidecar);

        let bundle = serde_json::from_slice::<StrictJsonValue>(CONSENSUS_CERTIFICATE_VECTORS)
            .unwrap()
            .0;
        let payload = bundle["payload"].as_object().unwrap();
        assert_eq!(
            bundle["payload_sha256"].as_str().unwrap(),
            hex::encode(Sha256::digest(serde_json::to_vec(payload).unwrap()))
        );
        assert_eq!(
            payload["profile"],
            "consensus-certificates-offline-evidence-only"
        );
        assert_eq!(payload["runtime_adoption_claim"], false);
        assert_eq!(payload["state_machine_claim"], false);
        assert_eq!(payload["signature_verification_claim"], true);
        assert_eq!(payload["quorum_verification_claim"], true);
        assert_eq!(payload["highest_qc_verification_claim"], true);
        assert_eq!(payload["historical_validator_set_verification_claim"], true);
        assert_eq!(payload["invalid_extra_fails_certificate"], true);

        let mut seeds = HashMap::new();
        for key in payload["test_keys"].as_array().unwrap() {
            assert_eq!(key["test_only"], true);
            let seed: [u8; 32] = hex::decode(key["seed_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let signing = SigningKey::from_bytes(&seed);
            let public = hex::encode(signing.verifying_key().to_bytes());
            assert_eq!(public, key["public_key_hex"].as_str().unwrap());
            assert!(seeds.insert(public, seed).is_none());
        }

        let cases = payload["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 24);
        let accepted = cases
            .iter()
            .filter(|case| case["expected"] == "accept")
            .collect::<Vec<_>>();
        assert_eq!(accepted.len(), 7);

        for case in &accepted {
            let object = case.as_object().unwrap();
            let mut body = object.clone();
            let claimed_id = body.remove("case_id").unwrap();
            assert_eq!(
                claimed_id,
                format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(serde_json::to_vec(&body).unwrap()))
                )
            );

            let mut artifacts = vec![&case["root"]];
            artifacts.extend(case["evidence"].as_array().unwrap());
            let mut index = HashMap::new();
            for artifact in &artifacts {
                verify_signed_evidence_artifact(artifact, &seeds, true).unwrap();
                let id = format!(
                    "{}:{}",
                    artifact["schema"].as_str().unwrap(),
                    artifact["digest_hex"].as_str().unwrap()
                );
                assert!(index.insert(id, *artifact).is_none());
            }

            let root = &case["root"];
            let root_source = root["source"].as_object().unwrap();
            let parent_height = root_source["parent_height"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap();
            let active = case["trusted_validator_history"]
                .as_array()
                .unwrap()
                .iter()
                .find(|history| {
                    verify_signed_evidence_artifact(&history["set"], &seeds, false).unwrap();
                    let set = history["set"]["source"].as_object().unwrap();
                    let first = history["first_parent_height"]
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap();
                    let last = history["last_parent_height"]
                        .as_str()
                        .unwrap()
                        .parse::<u128>()
                        .unwrap();
                    history["set"]["digest_hex"] == root_source["validator_set_commitment"]
                        && set["validator_set_epoch"] == root_source["validator_set_epoch"]
                        && (first..=last).contains(&parent_height)
                })
                .unwrap();
            let validator_keys = active["set"]["source"]["validator_public_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.as_str().unwrap().to_owned())
                .collect::<HashSet<_>>();
            let quorum = validator_keys.len() - (validator_keys.len() - 1) / 3;

            match root["schema"].as_str().unwrap() {
                "PrepareCertificate" => {
                    verify_rust_prepare_certificate(root, &index, &validator_keys, quorum)
                }
                "CommitCertificate" => {
                    verify_rust_commit_certificate(root, &index, &validator_keys, quorum)
                }
                "TimeoutCertificate" => {
                    verify_rust_timeout_certificate(root, &index, &validator_keys, quorum)
                }
                "ViewChangeProposal" => {
                    let tc = evidence_reference(
                        &index,
                        "TimeoutCertificate",
                        root_source["timeout_certificate_hash"].as_str().unwrap(),
                    );
                    verify_rust_timeout_certificate(tc, &index, &validator_keys, quorum);
                    let timed = tc["source"]["timed_out_round"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    let round = root_source["round"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    assert_eq!(round, timed.checked_add(1).unwrap());
                    let mut sorted_keys = validator_keys.iter().collect::<Vec<_>>();
                    sorted_keys.sort_unstable();
                    let leader_index = ((parent_height % sorted_keys.len() as u128)
                        + u128::from(round) % sorted_keys.len() as u128)
                        % sorted_keys.len() as u128;
                    assert_eq!(
                        root_source["proposer_public_key"].as_str().unwrap(),
                        sorted_keys[leader_index as usize].as_str()
                    );
                    for (proposal_name, tc_name) in [
                        ("high_prepare_qc_round", "selected_high_prepare_qc_round"),
                        (
                            "high_prepare_qc_block_id",
                            "selected_high_prepare_qc_block_id",
                        ),
                        ("high_prepare_qc_hash", "selected_high_prepare_qc_hash"),
                    ] {
                        assert_eq!(root_source.get(proposal_name), tc["source"].get(tc_name));
                    }
                    let prepare = evidence_reference(
                        &index,
                        "PrepareCertificate",
                        root_source["high_prepare_qc_hash"].as_str().unwrap(),
                    );
                    verify_rust_prepare_certificate(prepare, &index, &validator_keys, quorum);
                    assert_bound_fields(
                        root_source,
                        prepare["source"].as_object().unwrap(),
                        &[
                            "block_id",
                            "command_hash",
                            "expected_height",
                            "expected_state_root",
                        ],
                    );
                }
                other => panic!("unexpected accepted root schema {other}"),
            }
        }

        // The frozen non-canonical S+L mutation is rejected by dalek's strict
        // verifier, independently of the Go verifier's RFC 8032 checks.
        let noncanonical = cases
            .iter()
            .find(|case| case["name"] == "reject-noncanonical-ed25519-s-scalar")
            .unwrap();
        let member = &noncanonical["evidence"][0];
        assert_eq!(
            verify_signed_evidence_artifact(member, &seeds, true)
                .unwrap_err()
                .code,
            "invalid_signature"
        );

        let small_order = cases
            .iter()
            .find(|case| case["name"] == "reject-small-order-validator-key")
            .unwrap();
        let weak_member = small_order["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .find(|artifact| {
                artifact["source"]["voter_public_key"].as_str().unwrap()
                    == format!("01{}", "00".repeat(31))
            })
            .unwrap();
        assert_eq!(
            verify_signed_evidence_artifact(weak_member, &seeds, false)
                .unwrap_err()
                .code,
            "invalid_signature"
        );
    }

    #[test]
    fn readdressing_cannot_make_mutations_canonical() {
        let bundle = serde_json::from_slice::<StrictJsonValue>(VECTORS)
            .unwrap()
            .0;
        let cases = bundle["payload"]["cases"].as_array().unwrap();
        let accepted = cases
            .iter()
            .find(|case| case["name"] == "payment-intent-minimal")
            .unwrap();

        let mut leading_zero = accepted.clone();
        leading_zero["source"]["amount"] = Value::String("01".into());
        readdress_case(&mut leading_zero);
        assert_eq!(
            verify_vector_case(&leading_zero).unwrap_err().code,
            "noncanonical_number"
        );

        let mut reordered = accepted.clone();
        let wire = hex::decode(reordered["canonical_wire_hex"].as_str().unwrap()).unwrap();
        reordered["canonical_wire_hex"] = Value::String(swap_first_two_fields(&wire).encode_hex());
        readdress_case(&mut reordered);
        assert_eq!(
            verify_vector_case(&reordered).unwrap_err().code,
            "canonical_mismatch"
        );

        let mut missing = accepted.clone();
        missing["source"]
            .as_object_mut()
            .unwrap()
            .remove("source_zone");
        readdress_case(&mut missing);
        assert_eq!(
            verify_vector_case(&missing).unwrap_err().code,
            "missing_field"
        );
    }

    #[test]
    fn u64_expansion_is_exact_and_u128_downgrade_fails() {
        let value = u128::from(u64::MAX);
        assert_eq!(u64::try_from(value).unwrap(), u64::MAX);
        assert!(u64::try_from(value + 1).is_err());
        let source = json!({"value": (value + 1).to_string()});
        let wire = encode_source(WireSchema::LogicalHeight, source.as_object().unwrap()).unwrap();
        assert_eq!(
            decode_wire(WireSchema::LogicalHeight, &wire).unwrap()["value"],
            (value + 1).to_string()
        );
    }

    #[test]
    fn typed_value_risk_adapter_matches_frozen_vector_and_rejects_legacy_empty_hash() {
        let update = ValueRiskPolicyUpdate {
            update_id: "risk-0001".into(),
            zone_id: "zone-00112233445566778899".into(),
            currency_genesis_root: "11".repeat(32),
            protocol_era: 7,
            crypto_era: 3,
            policy_version: 1,
            previous_policy_sequence: 4,
            from_cap: ValueCap::ValueCap0,
            to_cap: ValueCap::ValueCap1,
            limits: ValueRiskLimits {
                max_single_transfer: Amount(1_000_000_000_000_000_000_000_000),
                max_local_value_total: Amount(100_000_000_000_000_000_000_000_000),
                max_cross_zone_exposure: Amount(25_000_000_000_000_000_000_000_000),
                max_dsc_exposure: Amount(5_000_000_000_000_000_000_000_000),
            },
            safety_case_hash: "77".repeat(32),
            safety_case_valid_until_height: 1_500,
            proposed_height: 1_000,
            activate_after_height: 1_100,
            expires_at_height: 1_400,
            nonce: 17,
            subject_hash: String::new(),
            validator_qc: empty_qc(),
            notary_qc: empty_qc(),
        };
        let bundle = serde_json::from_slice::<StrictJsonValue>(VECTORS)
            .unwrap()
            .0;
        let case = find_case(&bundle, "value-risk-policy-update");
        let wire = update
            .wire_v1_subject_bytes(RLDCOIN_TESTNET_DOMAIN)
            .unwrap();
        assert_eq!(hex::encode(&wire), case["canonical_wire_hex"]);
        assert_eq!(
            update.wire_v1_subject_hash(RLDCOIN_TESTNET_DOMAIN).unwrap(),
            case["sha256"]
        );
        assert_ne!(update.compute_subject_hash(), case["sha256"]);

        let mut legacy_cap_zero = update;
        legacy_cap_zero.to_cap = ValueCap::ValueCap0;
        legacy_cap_zero.safety_case_hash.clear();
        assert_eq!(
            legacy_cap_zero
                .wire_v1_subject_hash(RLDCOIN_MAINNET_DOMAIN)
                .unwrap_err()
                .code,
            "noncanonical_hex"
        );
    }

    #[test]
    fn typed_mainnet_consensus_signatures_and_commit_are_domain_separated() {
        let validators = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
        let validator_keys = validators
            .iter()
            .map(|validator| validator.public_key.clone())
            .collect::<Vec<_>>();
        let leader_key = deterministic_round_zero_leader(&validator_keys, u64::MAX - 1).unwrap();
        let leader = validators
            .iter()
            .find(|validator| validator.public_key == leader_key)
            .unwrap();
        let command = ConsensusCommand::ActivatePendingValueRiskPolicy;
        let command_hash = command
            .wire_v1_command_hash(RLDCOIN_MAINNET_DOMAIN)
            .unwrap();
        let mut proposal = ConsensusProposal {
            proposal_id: "proposal-mainnet-1".into(),
            zone_id: "zone-00112233445566778899".into(),
            currency_genesis_root: "11".repeat(32),
            protocol_era: 7,
            crypto_era: 3,
            parent_height: u64::MAX - 1,
            parent_state_root: "22".repeat(32),
            round: 0,
            proposer_public_key: leader.public_key.clone(),
            command_hash,
            command,
            expected_height: u64::MAX,
            expected_state_root: "44".repeat(32),
            signature: String::new(),
        };
        proposal.signature = sign_bytes(
            &leader.secret_key,
            &proposal
                .wire_v1_signing_bytes(RLDCOIN_MAINNET_DOMAIN)
                .unwrap(),
        )
        .unwrap();
        proposal.verify_wire_v1(RLDCOIN_MAINNET_DOMAIN).unwrap();
        assert!(proposal.verify_wire_v1(RLDCOIN_TESTNET_DOMAIN).is_err());
        assert!(proposal.verify().is_err());

        let proposal_hash = proposal
            .wire_v1_proposal_hash(RLDCOIN_MAINNET_DOMAIN)
            .unwrap();
        let votes = validators[..3]
            .iter()
            .map(|validator| {
                let mut vote = ConsensusVote {
                    proposal_id: proposal.proposal_id.clone(),
                    proposal_hash: proposal_hash.clone(),
                    zone_id: proposal.zone_id.clone(),
                    currency_genesis_root: proposal.currency_genesis_root.clone(),
                    protocol_era: proposal.protocol_era,
                    crypto_era: proposal.crypto_era,
                    parent_height: proposal.parent_height,
                    parent_state_root: proposal.parent_state_root.clone(),
                    round: proposal.round,
                    expected_state_root: proposal.expected_state_root.clone(),
                    voter_public_key: validator.public_key.clone(),
                    signature: String::new(),
                };
                vote.signature = sign_bytes(
                    &validator.secret_key,
                    &vote.wire_v1_signing_bytes(RLDCOIN_MAINNET_DOMAIN).unwrap(),
                )
                .unwrap();
                vote
            })
            .collect::<Vec<_>>();
        let commit = ConsensusCommit { proposal, votes };
        commit
            .verify_wire_v1(&validator_keys, RLDCOIN_MAINNET_DOMAIN)
            .unwrap();
        assert_ne!(
            commit.wire_v1_commit_hash(RLDCOIN_MAINNET_DOMAIN).unwrap(),
            commit.commit_hash()
        );
        assert!(commit
            .verify_wire_v1(&validator_keys, RLDCOIN_TESTNET_DOMAIN)
            .is_err());
    }

    #[test]
    fn mainnet_ledger_gate_rejects_legacy_proposal_signature() {
        let proposer = generate_identity();
        let ledger = Ledger::genesis_zone(
            "Wire-mainnet-gate",
            vec![proposer.public_key.clone()],
            Vec::new(),
            false,
        )
        .unwrap();
        let command = ConsensusCommand::ActivatePendingValueRiskPolicy;
        let command_hash = command
            .wire_v1_command_hash(&ledger.descriptor.network_domain)
            .unwrap();
        let mut proposal = ConsensusProposal {
            proposal_id: "proposal-mainnet-gate".into(),
            zone_id: ledger.descriptor.zone_id.clone(),
            currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
            protocol_era: ledger.descriptor.protocol_era,
            crypto_era: ledger.descriptor.crypto_era,
            parent_height: ledger.height,
            parent_state_root: ledger.state_root().unwrap(),
            round: 0,
            proposer_public_key: proposer.public_key.clone(),
            command_hash,
            command,
            expected_height: ledger.height + 1,
            expected_state_root: "44".repeat(32),
            signature: String::new(),
        };
        proposal.signature = sign_bytes(&proposer.secret_key, &proposal.signing_bytes()).unwrap();
        assert!(matches!(
            ledger.validate_consensus_proposal(&proposal),
            Err(LedgerError::InvalidQuorum(message)) if message.contains("invalid_signature")
        ));

        proposal.signature = sign_bytes(
            &proposer.secret_key,
            &proposal
                .wire_v1_signing_bytes(&ledger.descriptor.network_domain)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            ledger.validate_consensus_proposal(&proposal),
            Err(LedgerError::ValueRisk(_))
        ));
    }

    trait EncodeHex {
        fn encode_hex(&self) -> String;
    }

    impl EncodeHex for Vec<u8> {
        fn encode_hex(&self) -> String {
            hex::encode(self)
        }
    }

    fn verify_vector_case(case: &Value) -> WireResult<()> {
        let object = case
            .as_object()
            .ok_or_else(|| WireError::new("invalid_vector", "case must be an object"))?;
        let claimed_id = object["case_id"].as_str().unwrap();
        let mut body = object.clone();
        body.remove("case_id");
        let actual_id = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(&body).unwrap()))
        );
        if claimed_id != actual_id {
            return Err(WireError::new("case_hash_mismatch", actual_id));
        }
        let schema = WireSchema::try_from(object["schema"].as_str().unwrap())?;
        if object["expected"] == "accept" {
            let source = object["source"].as_object().unwrap();
            let wire = encode_source(schema, source)?;
            if hex::encode(&wire) != object["canonical_wire_hex"] {
                return Err(WireError::new(
                    "canonical_mismatch",
                    "frozen wire differs from Rust encoding",
                ));
            }
            if decode_wire(schema, &wire)? != *source {
                return Err(WireError::new(
                    "round_trip_mismatch",
                    "decoded source differs",
                ));
            }
            if let Some(context) = object.get("context").and_then(Value::as_object) {
                validate_context(schema, source, context)?;
            }
            let signing_preimage = preimage(schema, &wire);
            if hex::encode(&signing_preimage) != object["preimage_hex"] {
                return Err(WireError::new("preimage_mismatch", "preimage differs"));
            }
            if digest_hex(schema, &wire) != object["sha256"] {
                return Err(WireError::new("digest_mismatch", "digest differs"));
            }
            return Ok(());
        }
        let expected = object["expected_error"].as_str().unwrap();
        let observed = match object["mode"].as_str().unwrap() {
            "source" => encode_source(schema, object["source"].as_object().unwrap())
                .map(|_| ())
                .unwrap_err(),
            "source_json" => parse_strict_json_object(object["source_json"].as_str().unwrap())
                .and_then(|source| encode_source(schema, &source))
                .map(|_| ())
                .unwrap_err(),
            "wire" => decode_wire(
                schema,
                &hex::decode(object["encoded_wire_hex"].as_str().unwrap()).unwrap(),
            )
            .map(|_| ())
            .unwrap_err(),
            "context" => {
                let source = object["source"].as_object().unwrap();
                let wire = encode_source(schema, source)?;
                if hex::encode(&wire) != object["canonical_wire_hex"] {
                    return Err(WireError::new("canonical_mismatch", "context wire differs"));
                }
                let decoded = decode_wire(schema, &wire)?;
                validate_context(schema, &decoded, object["context"].as_object().unwrap())
                    .unwrap_err()
            }
            "preimage" => {
                let wire = encode_source(schema, object["source"].as_object().unwrap())?;
                let candidate =
                    hex::decode(object["candidate_preimage_hex"].as_str().unwrap()).unwrap();
                if candidate == preimage(schema, &wire) {
                    return Err(WireError::new(
                        "unexpected_accept",
                        "candidate preimage unexpectedly matched",
                    ));
                }
                WireError::new(
                    "signature_domain_substitution",
                    "candidate uses the wrong domain",
                )
            }
            mode => {
                return Err(WireError::new(
                    "invalid_vector",
                    format!("unknown mode {mode}"),
                ))
            }
        };
        if observed.code != expected {
            return Err(WireError::new(
                "wrong_reject_reason",
                format!("expected {expected}, observed {}", observed.code),
            ));
        }
        Ok(())
    }

    fn verify_signed_evidence_artifact(
        artifact: &Value,
        seeds: &std::collections::HashMap<String, [u8; 32]>,
        require_known_signer: bool,
    ) -> WireResult<()> {
        use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

        let schema = WireSchema::try_from(artifact["schema"].as_str().unwrap())?;
        let source = artifact["source"].as_object().unwrap();
        let wire = encode_source(schema, source)?;
        if hex::encode(&wire) != artifact["canonical_wire_hex"] {
            return Err(WireError::new(
                "evidence_digest_mismatch",
                "canonical wire differs",
            ));
        }
        if digest_hex(schema, &wire) != artifact["digest_hex"] {
            return Err(WireError::new("evidence_digest_mismatch", "digest differs"));
        }
        if schema.purpose() == WirePurpose::Subject {
            if artifact.get("signature_hex").is_some() {
                return Err(WireError::new(
                    "unexpected_signature",
                    "subject artifact carries a signature",
                ));
            }
            return Ok(());
        }

        let signature_hex = artifact["signature_hex"].as_str().unwrap();
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|_| WireError::new("invalid_signature_encoding", "signature hex"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| WireError::new("invalid_signature_encoding", "signature width"))?;
        let key_field = if schema == WireSchema::ViewChangeProposal {
            "proposer_public_key"
        } else {
            "voter_public_key"
        };
        let public_hex = source[key_field].as_str().unwrap();
        let public: [u8; 32] = hex::decode(public_hex)
            .map_err(|_| WireError::new("invalid_public_key_encoding", "public key hex"))?
            .try_into()
            .map_err(|_| WireError::new("invalid_public_key_encoding", "public key width"))?;
        let verifying = VerifyingKey::from_bytes(&public)
            .map_err(|_| WireError::new("invalid_public_key_encoding", "invalid point"))?;
        let image = preimage(schema, &wire);
        verifying
            .verify_strict(&image, &signature)
            .map_err(|_| WireError::new("invalid_signature", "strict Ed25519 rejection"))?;
        if require_known_signer {
            let seed = seeds
                .get(public_hex)
                .ok_or_else(|| WireError::new("unknown_test_key", public_hex))?;
            let signing = SigningKey::from_bytes(seed);
            if signing.verifying_key() != verifying
                || signing.sign(&image).to_bytes() != signature.to_bytes()
            {
                return Err(WireError::new(
                    "signature_reproduction_mismatch",
                    "seed-derived signature differs",
                ));
            }
        }
        Ok(())
    }

    fn evidence_reference<'a>(
        index: &'a std::collections::HashMap<String, &'a Value>,
        schema: &str,
        digest: &str,
    ) -> &'a Value {
        index
            .get(&format!("{schema}:{digest}"))
            .copied()
            .unwrap_or_else(|| panic!("missing {schema}:{digest}"))
    }

    fn consensus_binding_fields() -> &'static [&'static str] {
        &[
            "network_domain",
            "zone_id",
            "currency_genesis_root",
            "protocol_era",
            "crypto_era",
            "consensus_protocol_version",
            "validator_set_epoch",
            "validator_set_commitment",
            "parent_height",
            "parent_block_id",
            "parent_state_root",
        ]
    }

    fn value_binding_fields() -> Vec<&'static str> {
        let mut fields = consensus_binding_fields().to_vec();
        fields.extend([
            "round",
            "block_id",
            "proposal_hash",
            "command_hash",
            "expected_height",
            "expected_state_root",
        ]);
        fields
    }

    fn assert_bound_fields(left: &Map<String, Value>, right: &Map<String, Value>, fields: &[&str]) {
        for field in fields {
            assert_eq!(left.get(*field), right.get(*field), "binding {field}");
        }
    }

    fn verify_rust_prepare_certificate(
        certificate: &Value,
        index: &std::collections::HashMap<String, &Value>,
        validator_keys: &std::collections::HashSet<String>,
        quorum: usize,
    ) {
        let source = certificate["source"].as_object().unwrap();
        let mut signers = std::collections::HashSet::new();
        for hash in source["prepare_vote_hashes"].as_array().unwrap() {
            let vote = evidence_reference(index, "PrepareVote", hash.as_str().unwrap());
            assert_bound_fields(
                source,
                vote["source"].as_object().unwrap(),
                &value_binding_fields(),
            );
            let signer = vote["source"]["voter_public_key"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(validator_keys.contains(&signer));
            assert!(signers.insert(signer));
        }
        assert!(signers.len() >= quorum);
    }

    fn verify_rust_commit_certificate(
        certificate: &Value,
        index: &std::collections::HashMap<String, &Value>,
        validator_keys: &std::collections::HashSet<String>,
        quorum: usize,
    ) {
        let source = certificate["source"].as_object().unwrap();
        let prepare_hash = source["prepare_certificate_hash"].as_str().unwrap();
        let prepare = evidence_reference(index, "PrepareCertificate", prepare_hash);
        verify_rust_prepare_certificate(prepare, index, validator_keys, quorum);
        assert_bound_fields(
            source,
            prepare["source"].as_object().unwrap(),
            &value_binding_fields(),
        );
        let mut signers = std::collections::HashSet::new();
        for hash in source["commit_vote_hashes"].as_array().unwrap() {
            let vote = evidence_reference(index, "CommitVote", hash.as_str().unwrap());
            let vote_source = vote["source"].as_object().unwrap();
            assert_bound_fields(source, vote_source, &value_binding_fields());
            assert_eq!(vote_source["prepare_certificate_hash"], prepare_hash);
            let signer = vote_source["voter_public_key"].as_str().unwrap().to_owned();
            assert!(validator_keys.contains(&signer));
            assert!(signers.insert(signer));
        }
        assert!(signers.len() >= quorum);
    }

    fn verify_rust_timeout_certificate(
        certificate: &Value,
        index: &std::collections::HashMap<String, &Value>,
        validator_keys: &std::collections::HashSet<String>,
        quorum: usize,
    ) {
        let source = certificate["source"].as_object().unwrap();
        let mut timeout_bindings = consensus_binding_fields().to_vec();
        timeout_bindings.push("timed_out_round");
        let mut signers = std::collections::HashSet::new();
        let mut reports = Vec::new();
        for hash in source["timeout_vote_hashes"].as_array().unwrap() {
            let vote = evidence_reference(index, "TimeoutVote", hash.as_str().unwrap());
            let vote_source = vote["source"].as_object().unwrap();
            assert_bound_fields(source, vote_source, &timeout_bindings);
            let signer = vote_source["voter_public_key"].as_str().unwrap().to_owned();
            assert!(validator_keys.contains(&signer));
            assert!(signers.insert(signer));
            if let Some(high_hash) = vote_source
                .get("high_prepare_qc_hash")
                .and_then(Value::as_str)
            {
                let prepare = evidence_reference(index, "PrepareCertificate", high_hash);
                verify_rust_prepare_certificate(prepare, index, validator_keys, quorum);
                assert_bound_fields(
                    vote_source,
                    prepare["source"].as_object().unwrap(),
                    consensus_binding_fields(),
                );
                assert_eq!(
                    vote_source["high_prepare_qc_round"],
                    prepare["source"]["round"]
                );
                assert_eq!(
                    vote_source["high_prepare_qc_block_id"],
                    prepare["source"]["block_id"]
                );
                reports.push((
                    vote_source["high_prepare_qc_round"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                    vote_source["high_prepare_qc_block_id"].as_str().unwrap(),
                    high_hash,
                ));
            }
        }
        assert!(signers.len() >= quorum);
        if reports.is_empty() {
            assert!(source.get("selected_high_prepare_qc_hash").is_none());
            return;
        }
        reports.sort_unstable_by_key(|report| std::cmp::Reverse(report.0));
        let highest = reports[0];
        for report in reports
            .iter()
            .skip(1)
            .take_while(|report| report.0 == highest.0)
        {
            assert_eq!((report.1, report.2), (highest.1, highest.2));
        }
        assert_eq!(
            source["selected_high_prepare_qc_round"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            highest.0
        );
        assert_eq!(
            source["selected_high_prepare_qc_block_id"]
                .as_str()
                .unwrap(),
            highest.1
        );
        assert_eq!(
            source["selected_high_prepare_qc_hash"].as_str().unwrap(),
            highest.2
        );
    }

    fn find_case<'a>(bundle: &'a Value, name: &str) -> &'a Value {
        bundle["payload"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap()
    }

    fn empty_qc() -> QuorumCertificate {
        QuorumCertificate {
            subject_hash: String::new(),
            threshold: 0,
            attestations: Vec::new(),
            testnet_simulated: true,
        }
    }

    fn readdress_case(case: &mut Value) {
        let object = case.as_object_mut().unwrap();
        object.remove("case_id");
        let id = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(serde_json::to_vec(object).unwrap()))
        );
        object.insert("case_id".into(), Value::String(id));
    }

    fn swap_first_two_fields(wire: &[u8]) -> Vec<u8> {
        let count = usize::from(u16::from_be_bytes([wire[8], wire[9]]));
        assert!(count >= 2);
        let mut offset = 10;
        let mut entries = Vec::new();
        for _ in 0..count {
            let length = u32::from_be_bytes([
                wire[offset + 3],
                wire[offset + 4],
                wire[offset + 5],
                wire[offset + 6],
            ]) as usize;
            let end = offset + 7 + length;
            entries.push(wire[offset..end].to_vec());
            offset = end;
        }
        entries.swap(0, 1);
        let mut result = wire[..10].to_vec();
        result.extend(entries.into_iter().flatten());
        result
    }
}
