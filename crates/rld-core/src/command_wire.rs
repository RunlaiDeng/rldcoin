//! Explicit, versioned RLD-WIRE-V1 command commitments.
//!
//! The command payload serializer below is intentionally not a JSON codec and
//! does not inherit Serde's data-model choices. Every reachable struct,
//! struct field, unit enum, and enum variant has a frozen numeric identifier.
//! An unregistered type or field fails closed.

use std::fmt;

use serde::{
    ser::{Impossible, SerializeSeq, SerializeStruct, Serializer},
    Serialize,
};
use unicode_normalization::UnicodeNormalization;

use crate::{
    admission::AdmissionCheckpointProofV1,
    wire::{
        digest_hex, encode_command_commitment, encode_reserved_command_commitment_candidate,
        WireError, WireSchema,
    },
    ConsensusCommand, ProductionCommand,
};

const PAYLOAD_MAGIC: &[u8; 4] = b"RLDP";
const PAYLOAD_VERSION: u16 = 1;

#[derive(Clone, Copy)]
enum Semantic {
    Normal,
    Amount,
    Hash32,
    Key32,
    Signature64,
    CanonicalSet,
}

#[derive(Clone, Copy)]
struct FieldRule {
    id: u16,
    name: &'static str,
    semantic: Semantic,
    required: bool,
}

#[derive(Clone, Copy)]
struct StructSchema {
    id: u16,
    name: &'static str,
    fields: &'static [FieldRule],
}

macro_rules! field {
    ($id:literal, $name:literal, $semantic:ident) => {
        FieldRule {
            id: $id,
            name: $name,
            semantic: Semantic::$semantic,
            required: true,
        }
    };
    ($id:literal, $name:literal, $semantic:ident, optional) => {
        FieldRule {
            id: $id,
            name: $name,
            semantic: Semantic::$semantic,
            required: false,
        }
    };
}

macro_rules! schema {
    ($id:literal, $name:literal, [$( $field:expr ),* $(,)?]) => {
        StructSchema { id: $id, name: $name, fields: &[$($field),*] }
    };
}

fn struct_schema(name: &str) -> Option<StructSchema> {
    Some(match name {
        "ZoneDescriptor" => schema!(
            0x1001,
            "ZoneDescriptor",
            [
                field!(1, "zone_id", Normal),
                field!(2, "display_name", Normal),
                field!(3, "genesis_root", Hash32),
                field!(4, "identity_version", Normal),
                field!(5, "identity_hash_suite", Normal),
                field!(6, "network_domain", Normal),
                field!(7, "anchor_supply", Amount),
                field!(8, "genesis_validator_keys", Key32),
                field!(9, "genesis_notary_keys", Key32),
                field!(10, "currency_genesis_root", Hash32),
                field!(11, "validator_keys", Key32),
                field!(12, "notary_keys", Key32),
                field!(13, "protocol_era", Normal),
                field!(14, "crypto_era", Normal),
                field!(15, "testnet", Normal),
            ]
        ),
        "ValueRiskLimits" => schema!(
            0x1002,
            "ValueRiskLimits",
            [
                field!(1, "max_single_transfer", Amount),
                field!(2, "max_local_value_total", Amount),
                field!(3, "max_cross_zone_exposure", Amount),
                field!(4, "max_dsc_exposure", Amount),
            ]
        ),
        "ValueRiskPolicyUpdate" => schema!(
            0x1003,
            "ValueRiskPolicyUpdate",
            [
                field!(1, "update_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "policy_version", Normal),
                field!(7, "previous_policy_sequence", Normal),
                field!(8, "from_cap", Normal),
                field!(9, "to_cap", Normal),
                field!(10, "limits", Normal),
                field!(11, "safety_case_hash", Hash32),
                field!(12, "safety_case_valid_until_height", Normal),
                field!(13, "proposed_height", Normal),
                field!(14, "activate_after_height", Normal),
                field!(15, "expires_at_height", Normal),
                field!(16, "nonce", Normal),
                field!(17, "subject_hash", Hash32),
                field!(18, "validator_qc", Normal),
                field!(19, "notary_qc", Normal),
            ]
        ),
        "ZoneAdvertisement" => schema!(
            0x1004,
            "ZoneAdvertisement",
            [
                field!(1, "descriptor", Normal),
                field!(2, "sequence", Normal),
                field!(3, "endpoints", Normal),
                field!(4, "neighboring_zone_ids", Normal),
                field!(5, "transports", Normal),
                field!(6, "subject_hash", Hash32),
                field!(7, "validator_qc", Normal),
            ]
        ),
        "PaymentRequest" => schema!(
            0x1005,
            "PaymentRequest",
            [
                field!(1, "request_id", Normal),
                field!(2, "recipient", Normal),
                field!(3, "recipient_public_key", Key32),
                field!(4, "destination_zone", Normal),
                field!(5, "currency_genesis_root", Hash32),
                field!(6, "protocol_era", Normal),
                field!(7, "crypto_era", Normal),
                field!(8, "amount", Amount),
                field!(9, "memo", Normal),
                field!(10, "expires_at_height", Normal),
                field!(11, "nonce", Normal),
                field!(12, "signature", Signature64),
            ]
        ),
        "UniversalPaymentIntent" => schema!(
            0x1006,
            "UniversalPaymentIntent",
            [
                field!(1, "payment_id", Normal),
                field!(2, "source_zone", Normal),
                field!(3, "destination_zone", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "pricing_epoch", Normal),
                field!(8, "sender_public_key", Key32),
                field!(9, "recipient", Normal),
                field!(10, "coin_id", Normal),
                field!(11, "amount", Amount),
                field!(12, "max_fee", Amount),
                field!(13, "nonce", Normal),
                field!(14, "payment_request_id", Normal, optional),
                field!(15, "payment_request", Normal, optional),
                field!(16, "route_quote_id", Normal, optional),
                field!(17, "signature", Signature64),
            ]
        ),
        "SignedActionAuthorization" => schema!(
            0x1007,
            "SignedActionAuthorization",
            [
                field!(1, "authorization_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "signer_public_key", Key32),
                field!(7, "action", Normal),
                field!(8, "payload_hash", Hash32),
                field!(9, "nonce", Normal),
                field!(10, "signature", Signature64),
            ]
        ),
        "CreateRouteQuoteRequest" => schema!(
            0x1008,
            "CreateRouteQuoteRequest",
            [
                field!(1, "provider", Normal),
                field!(2, "destination_zone", Normal),
                field!(3, "route", Normal),
                field!(4, "transport", Normal),
                field!(5, "base_fee", Amount),
                field!(6, "authorized_reroute_budget", Amount),
                field!(7, "expires_at_height", Normal),
                field!(8, "authorization", Normal),
            ]
        ),
        "RerouteRouteQuoteRequest" => schema!(
            0x1009,
            "RerouteRouteQuoteRequest",
            [
                field!(1, "failed_hop", Normal),
                field!(2, "replacement_route", Normal),
                field!(3, "incremental_fee", Amount),
                field!(4, "authorization", Normal),
            ]
        ),
        "SignedAttestation" => schema!(
            0x100a,
            "SignedAttestation",
            [
                field!(1, "public_key", Key32),
                field!(2, "signature", Signature64),
            ]
        ),
        "QuorumCertificate" => schema!(
            0x100b,
            "QuorumCertificate",
            [
                field!(1, "subject_hash", Hash32),
                field!(2, "threshold", Normal),
                field!(3, "attestations", CanonicalSet),
                field!(4, "testnet_simulated", Normal),
            ]
        ),
        "CryptoSuiteDescriptor" => schema!(
            0x100c,
            "CryptoSuiteDescriptor",
            [
                field!(1, "suite_id", Normal),
                field!(2, "signature_algorithm", Normal),
                field!(3, "hash_algorithm", Normal),
                field!(4, "encoding", Normal),
            ]
        ),
        "EraContinuityCertificate" => schema!(
            0x100d,
            "EraContinuityCertificate",
            [
                field!(1, "zone_id", Normal),
                field!(2, "previous_protocol_era", Normal),
                field!(3, "new_protocol_era", Normal),
                field!(4, "previous_crypto_era", Normal),
                field!(5, "new_crypto_era", Normal),
                field!(6, "previous_certificate_hash", Hash32),
                field!(7, "activation_checkpoint", Hash32),
                field!(8, "irreversible_height", Normal),
                field!(9, "new_suite", Normal),
                field!(10, "previous_validator_keys", Key32),
                field!(11, "previous_notary_keys", Key32),
                field!(12, "new_validator_keys", Key32),
                field!(13, "new_notary_keys", Key32),
                field!(14, "old_crypto_qc", Normal),
                field!(15, "new_crypto_qc", Normal),
                field!(16, "notary_qc", Normal),
                field!(17, "certificate_hash", Hash32),
            ]
        ),
        "OperationalProof" => schema!(
            0x100e,
            "OperationalProof",
            [
                field!(1, "checkpoint_hash", Hash32),
                field!(2, "object_hash", Hash32),
                field!(3, "continuity_accumulator", Hash32),
                field!(4, "lineage_merkle_path", Hash32),
                field!(5, "transition_hashes", Hash32),
                field!(6, "protocol_era", Normal),
                field!(7, "crypto_era", Normal),
                field!(8, "era_certificate_hash", Hash32),
                field!(9, "supply_certificate_hash", Hash32),
                field!(10, "transit_nullifier_commitment", Hash32),
            ]
        ),
        "CoinObject" => schema!(
            0x100f,
            "CoinObject",
            [
                field!(1, "object_id", Normal),
                field!(2, "lineage_root", Hash32),
                field!(3, "parent_ids", Normal),
                field!(4, "owner", Normal),
                field!(5, "zone_id", Normal),
                field!(6, "amount", Amount),
                field!(7, "state", Normal),
                field!(8, "version", Normal),
                field!(9, "created_height", Normal),
                field!(10, "transit_id", Normal),
                field!(11, "imported_from", Normal),
                field!(12, "origin_zone", Normal),
                field!(13, "origin_genesis_root", Hash32),
            ]
        ),
        "SupplyBuckets" => schema!(
            0x1010,
            "SupplyBuckets",
            [
                field!(1, "reserve", Amount),
                field!(2, "fee_pools", Amount),
                field!(3, "spendable", Amount),
                field!(4, "reserved", Amount),
                field!(5, "in_transit", Amount),
                field!(6, "returning", Amount),
                field!(7, "quarantined", Amount),
                field!(8, "imported_total", Amount),
                field!(9, "finalized_export_total", Amount),
            ]
        ),
        "ProtocolReservePools" => schema!(
            0x1011,
            "ProtocolReservePools",
            [
                field!(1, "startup_services", Amount),
                field!(2, "continuity_services", Amount),
                field!(3, "demand_matching", Amount),
            ]
        ),
        "SupplyConservationCertificate" => schema!(
            0x1012,
            "SupplyConservationCertificate",
            [
                field!(1, "zone_id", Normal),
                field!(2, "height", Normal),
                field!(3, "merkle_sum_root", Hash32),
                field!(4, "buckets", Normal),
                field!(5, "reserve_pools", Normal),
                field!(6, "conservation_position", Amount),
                field!(7, "anchor_supply", Amount),
                field!(8, "valid", Normal),
            ]
        ),
        "GatewayEndorsement" => schema!(
            0x1013,
            "GatewayEndorsement",
            [
                field!(1, "bond_id", Normal),
                field!(2, "source_zone", Normal),
                field!(3, "gateway_public_key", Key32),
                field!(4, "capsule_subject_hash", Hash32),
                field!(5, "signature", Signature64),
            ]
        ),
        "TransitCapsule" => schema!(
            0x1014,
            "TransitCapsule",
            [
                field!(1, "transit_id", Normal),
                field!(2, "payment_id", Normal),
                field!(3, "payment_request_id", Normal, optional),
                field!(4, "payment_request", Normal, optional),
                field!(5, "route_quote_id", Normal, optional),
                field!(6, "source_zone", Normal),
                field!(7, "destination_zone", Normal),
                field!(8, "source_descriptor", Normal),
                field!(9, "recipient", Normal),
                field!(10, "amount", Amount),
                field!(11, "lineage_root", Hash32),
                field!(12, "source_object_id", Normal),
                field!(13, "source_object_version", Normal),
                field!(14, "source_object", Normal),
                field!(15, "source_supply", Normal),
                field!(16, "origin_genesis_root", Hash32),
                field!(17, "source_checkpoint", Hash32),
                field!(18, "validator_qc", Normal),
                field!(19, "notary_qc", Normal),
                field!(20, "operational_proof", Normal),
                field!(21, "era_certificate", Normal),
                field!(22, "gateway_endorsement", Normal, optional),
                field!(23, "transport", Normal),
            ]
        ),
        "CreateGatewayBondRequest" => schema!(
            0x1015,
            "CreateGatewayBondRequest",
            [
                field!(1, "source_zone", Normal),
                field!(2, "owner", Normal),
                field!(3, "gateway_public_key", Key32),
                field!(4, "coin_id", Normal),
                field!(5, "amount", Amount),
                field!(6, "authorization", Normal),
            ]
        ),
        "DestinationRejectionProof" => schema!(
            0x1016,
            "DestinationRejectionProof",
            [
                field!(1, "rejection_id", Normal),
                field!(2, "transit_id", Normal),
                field!(3, "payment_id", Normal),
                field!(4, "source_zone", Normal),
                field!(5, "destination_zone", Normal),
                field!(6, "source_object_id", Normal),
                field!(7, "source_object_version", Normal),
                field!(8, "recipient", Normal),
                field!(9, "amount", Amount),
                field!(10, "reason", Normal),
                field!(11, "destination_descriptor", Normal),
                field!(12, "destination_height", Normal),
                field!(13, "destination_checkpoint", Hash32),
                field!(14, "validator_qc", Normal),
                field!(15, "notary_qc", Normal),
            ]
        ),
        "DestinationImportReceipt" => schema!(
            0x1017,
            "DestinationImportReceipt",
            [
                field!(1, "transit_id", Normal),
                field!(2, "payment_id", Normal),
                field!(3, "destination_zone", Normal),
                field!(4, "destination_coin_id", Normal),
                field!(5, "recipient", Normal),
                field!(6, "amount", Amount),
                field!(7, "destination_height", Normal),
                field!(8, "checkpoint_hash", Hash32),
            ]
        ),
        "RecipientReceipt" => schema!(
            0x1018,
            "RecipientReceipt",
            [
                field!(1, "receipt_id", Normal),
                field!(2, "payment_id", Normal),
                field!(3, "settlement_reference", Normal),
                field!(4, "destination_zone", Normal),
                field!(5, "currency_genesis_root", Hash32),
                field!(6, "protocol_era", Normal),
                field!(7, "crypto_era", Normal),
                field!(8, "recipient", Normal),
                field!(9, "recipient_public_key", Key32),
                field!(10, "amount", Amount),
                field!(11, "observed_destination_height", Normal),
                field!(12, "nonce", Normal),
                field!(13, "signature", Signature64),
            ]
        ),
        "SpendabilityCertificateRequest" => schema!(
            0x1019,
            "SpendabilityCertificateRequest",
            [
                field!(1, "payment_id", Normal),
                field!(2, "provider_coin_id", Normal),
                field!(3, "liquidity_provider", Normal),
                field!(4, "recipient", Normal),
                field!(5, "amount", Amount),
                field!(6, "settlement_claim_transit_id", Normal),
                field!(7, "authorization", Normal),
            ]
        ),
        "CreateLiquidityOfferRequest" => schema!(
            0x101a,
            "CreateLiquidityOfferRequest",
            [
                field!(1, "provider", Normal),
                field!(2, "coin_id", Normal),
                field!(3, "amount", Amount),
                field!(4, "minimum", Amount),
                field!(5, "maximum", Amount),
                field!(6, "expires_at_height", Normal),
                field!(7, "authorization", Normal),
            ]
        ),
        "TakeLiquidityOfferRequest" => schema!(
            0x101b,
            "TakeLiquidityOfferRequest",
            [
                field!(1, "offer_id", Normal),
                field!(2, "settlement_claim", Normal),
            ]
        ),
        "TravelerCarryCapsule" => schema!(
            0x101c,
            "TravelerCarryCapsule",
            [
                field!(1, "capsule_id", Normal),
                field!(2, "owner", Normal),
                field!(3, "issued_height", Normal),
                field!(4, "transit", Normal),
            ]
        ),
        "ProtocolServiceOrderRequest" => schema!(
            0x101d,
            "ProtocolServiceOrderRequest",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "reserve_pool", Normal),
                field!(4, "role", Normal),
                field!(5, "budget", Amount),
                field!(6, "description", Normal),
                field!(7, "matched_service_receipt_id", Normal),
                field!(8, "protocol_era", Normal),
                field!(9, "crypto_era", Normal),
                field!(10, "nonce", Normal),
                field!(11, "subject_hash", Hash32),
                field!(12, "validator_qc", Normal),
                field!(13, "notary_qc", Normal),
            ]
        ),
        "EconomicControlMember" => schema!(
            0x101e,
            "EconomicControlMember",
            [
                field!(1, "subject_id", Normal),
                field!(2, "control_group_id", Normal),
                field!(3, "role", Normal),
                field!(4, "validator_vote_bps", Normal),
            ]
        ),
        "EconomicControlAttestation" => schema!(
            0x101f,
            "EconomicControlAttestation",
            [
                field!(1, "attestation_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "protocol_era", Normal),
                field!(4, "crypto_era", Normal),
                field!(5, "issued_height", Normal),
                field!(6, "valid_until_height", Normal),
                field!(7, "evidence_hash", Hash32),
                field!(8, "auditor_public_key", Key32),
                field!(9, "auditor_control_group_id", Normal),
                field!(10, "members", Normal),
                field!(11, "auditor_signature", Signature64),
                field!(12, "validator_qc", Normal),
                field!(13, "notary_qc", Normal),
            ]
        ),
        "EconomicPriceAttestation" => schema!(
            0x1020,
            "EconomicPriceAttestation",
            [
                field!(1, "attestation_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "work_id", Normal),
                field!(4, "control_attestation_id", Normal),
                field!(5, "source_public_key", Key32),
                field!(6, "source_control_group_id", Normal),
                field!(7, "amount", Amount),
                field!(8, "issued_height", Normal),
                field!(9, "valid_until_height", Normal),
                field!(10, "evidence_hash", Hash32),
                field!(11, "signature", Signature64),
            ]
        ),
        "EconomicReleasePolicy" => schema!(
            0x1021,
            "EconomicReleasePolicy",
            [
                field!(1, "policy_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "protocol_era", Normal),
                field!(4, "crypto_era", Normal),
                field!(5, "era_id", Normal),
                field!(6, "reserve_pool", Normal),
                field!(7, "era_release_cap", Amount),
                field!(8, "released", Amount),
                field!(9, "starts_at_height", Normal),
                field!(10, "ends_after_height", Normal),
                field!(11, "minimum_bond_coverage_bps", Normal),
                field!(12, "validator_qc", Normal),
                field!(13, "notary_qc", Normal),
            ]
        ),
        "ProtocolServiceBondLockRequest" => schema!(
            0x1022,
            "ProtocolServiceBondLockRequest",
            [
                field!(1, "bond_id", Normal),
                field!(2, "order_id", Normal),
                field!(3, "lease_id", Normal),
                field!(4, "owner", Normal),
                field!(5, "coin_id", Normal),
                field!(6, "amount", Amount),
                field!(7, "challenge_end_height", Normal),
                field!(8, "unbond_after_height", Normal),
                field!(9, "slash_conditions_hash", Hash32),
                field!(10, "authorization", Normal),
            ]
        ),
        "ProtocolServiceBondSlash" => schema!(
            0x1023,
            "ProtocolServiceBondSlash",
            [
                field!(1, "slash_id", Normal),
                field!(2, "bond_id", Normal),
                field!(3, "amount", Amount),
                field!(4, "evidence_hash", Hash32),
                field!(5, "validator_qc", Normal),
                field!(6, "notary_qc", Normal),
            ]
        ),
        "ProtocolReserveReleaseRequest" => schema!(
            0x1024,
            "ProtocolReserveReleaseRequest",
            [
                field!(1, "release_id", Normal),
                field!(2, "order_id", Normal),
                field!(3, "lease_id", Normal),
                field!(4, "requester_subject_id", Normal),
                field!(5, "work_id", Normal),
                field!(6, "work_proof_hash", Hash32),
                field!(7, "fee_receipt_ids", Normal),
                field!(8, "control_attestation_id", Normal),
                field!(9, "price_attestation_ids", Normal),
                field!(10, "bond_id", Normal),
                field!(11, "release_policy_id", Normal),
                field!(12, "reward", Amount),
                field!(13, "provider_authorization", Normal),
                field!(14, "completion_validator_qc", Normal),
                field!(15, "completion_notary_qc", Normal),
            ]
        ),
        "StakeAuthorityPolicyCommandV1" => schema!(
            0x1025,
            "StakeAuthorityPolicyCommandV1",
            [
                field!(1, "policy_version", Normal),
                field!(2, "minimum_self_bond", Amount),
                field!(3, "minimum_delegation", Amount),
                field!(4, "candidate_maturity_blocks", Normal),
                field!(5, "stake_maturity_blocks", Normal),
                field!(6, "evidence_window_blocks", Normal),
                field!(7, "activation_delay_blocks", Normal),
                field!(8, "epoch_length_blocks", Normal),
                field!(9, "maximum_validators", Normal),
            ]
        ),
        "StakeAuthorityCandidateCommandV1" => schema!(
            0x1026,
            "StakeAuthorityCandidateCommandV1",
            [
                field!(1, "validator_id", Normal),
                field!(2, "owner", Normal),
                field!(3, "public_key", Key32),
                field!(4, "key_era", Normal),
                field!(5, "registered_height", Normal),
                field!(6, "exit_height", Normal),
                field!(7, "proof_of_possession", Signature64),
            ]
        ),
        "StakeAuthorityPositionCommandV1" => schema!(
            0x1027,
            "StakeAuthorityPositionCommandV1",
            [
                field!(1, "position_id", Normal),
                field!(2, "position_type", Normal),
                field!(3, "validator_id", Normal),
                field!(4, "owner", Normal),
                field!(5, "source_coin_id", Normal),
                field!(6, "escrow_coin_id", Normal),
                field!(7, "amount", Amount),
                field!(8, "locked_height", Normal),
                field!(9, "committed_through_height", Normal),
            ]
        ),
        "StakeUboControlRecordCommandV1" => schema!(
            0x1028,
            "StakeUboControlRecordCommandV1",
            [
                field!(1, "control_group", Normal),
                field!(2, "valid_from_height", Normal),
                field!(3, "challenge_ends_height", Normal),
                field!(4, "valid_through_height", Normal),
                field!(5, "evidence_hash", Hash32),
            ]
        ),
        "StakeUboControlEntryV1" => schema!(
            0x1029,
            "StakeUboControlEntryV1",
            [
                field!(1, "validator_id", Normal),
                field!(2, "record", Normal),
            ]
        ),
        "StakeAuthorityGovernanceUpdateV1" => schema!(
            0x102a,
            "StakeAuthorityGovernanceUpdateV1",
            [
                field!(1, "update_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "authority_version", Normal),
                field!(9, "sequence", Normal),
                field!(10, "expected_previous_commitment", Hash32),
                field!(11, "policy", Normal),
                field!(12, "candidates", Normal),
                field!(13, "positions", Normal),
                field!(14, "ubo_map_version", Normal),
                field!(15, "ubo_sequence", Normal),
                field!(16, "ubo_predecessor_commitment", Hash32),
                field!(17, "ubo_verifier_set_commitment", Hash32),
                field!(18, "ubo_evidence_root", Hash32),
                field!(19, "ubo_validators", Normal),
                field!(20, "prospective_authority_commitment", Hash32),
                field!(21, "subject_hash", Hash32),
                field!(22, "validator_qc", Normal),
                field!(23, "notary_qc", Normal),
            ]
        ),
        "DeriveNextStakeEpochRequestV1" => schema!(
            0x102b,
            "DeriveNextStakeEpochRequestV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "expected_consensus_epoch", Normal),
                field!(11, "expected_snapshot_height", Normal),
                field!(12, "expected_snapshot_state_root", Hash32),
            ]
        ),
        "LockConsensusStakeRequestV1" => schema!(
            0x102c,
            "LockConsensusStakeRequestV1",
            [
                field!(1, "position_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_type", Normal),
                field!(11, "validator_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "source_coin_id", Normal),
                field!(14, "amount", Amount),
                field!(15, "committed_through_height", Normal),
                field!(16, "authorization", Normal),
            ]
        ),
        "RegisterConsensusValidatorRequestV1" => schema!(
            0x102d,
            "RegisterConsensusValidatorRequestV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "validator_id", Normal),
                field!(11, "owner", Normal),
                field!(12, "public_key", Key32),
                field!(13, "key_era", Normal),
                field!(14, "proof_of_possession", Signature64),
                field!(15, "authorization", Normal),
            ]
        ),
        "ExitConsensusValidatorRequestV1" => schema!(
            0x102e,
            "ExitConsensusValidatorRequestV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "validator_id", Normal),
                field!(11, "owner", Normal),
                field!(12, "public_key", Key32),
                field!(13, "key_era", Normal),
                field!(14, "registered_height", Normal),
                field!(15, "exit_height", Normal),
                field!(16, "proof_of_possession", Signature64),
                field!(17, "authorization", Normal),
            ]
        ),
        "RequestConsensusStakeUnbondV1" => schema!(
            0x102f,
            "RequestConsensusStakeUnbondV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_id", Normal),
                field!(11, "escrow_coin_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "beneficiary", Normal),
                field!(14, "requested_withdraw_after_height", Normal),
                field!(15, "authorization", Normal),
            ]
        ),
        "CompleteConsensusStakeUnbondV1" => schema!(
            0x1030,
            "CompleteConsensusStakeUnbondV1",
            [
                field!(1, "completion_id", Normal),
                field!(2, "request_id", Normal),
                field!(3, "zone_id", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "proposed_height", Normal),
                field!(8, "expires_at_height", Normal),
                field!(9, "expected_unbond_request_commitment", Hash32),
                field!(10, "beneficiary", Normal),
            ]
        ),
        "LockConsensusStakeRequestV2" => schema!(
            0x1031,
            "LockConsensusStakeRequestV2",
            [
                field!(1, "position_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_type", Normal),
                field!(11, "validator_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "source_coin_id", Normal),
                field!(14, "amount", Amount),
                field!(15, "committed_through_height", Normal),
                field!(16, "slash_terms_authorization", Normal),
                field!(17, "authorization", Normal),
            ]
        ),
        "MigrateConsensusStakeSlashTermsV2" => schema!(
            0x1032,
            "MigrateConsensusStakeSlashTermsV2",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_id", Normal),
                field!(11, "escrow_coin_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "slash_terms_authorization", Normal),
                field!(14, "authorization", Normal),
            ]
        ),
        "SignedConsensusVoteStatementV1" => schema!(
            0x1033,
            "SignedConsensusVoteStatementV1",
            [
                field!(1, "proposal_id", Normal),
                field!(2, "proposal_hash", Hash32),
                field!(3, "zone_id", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "parent_height", Normal),
                field!(8, "parent_state_root", Hash32),
                field!(9, "round", Normal),
                field!(10, "expected_state_root", Hash32),
                field!(11, "voter_public_key", Key32),
                field!(12, "signature", Signature64),
            ]
        ),
        "SignedConsensusProposalStatementV1" => schema!(
            0x1034,
            "SignedConsensusProposalStatementV1",
            [
                field!(1, "proposal_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "parent_height", Normal),
                field!(7, "parent_state_root", Hash32),
                field!(8, "round", Normal),
                field!(9, "proposer_public_key", Key32),
                field!(10, "command_hash", Hash32),
                field!(11, "expected_height", Normal),
                field!(12, "expected_state_root", Hash32),
                field!(13, "signature", Signature64),
            ]
        ),
        "SignedConsensusCheckpointStatementV1" => schema!(
            0x1035,
            "SignedConsensusCheckpointStatementV1",
            [
                field!(1, "network_domain", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "consensus_protocol_version", Normal),
                field!(7, "consensus_epoch", Normal),
                field!(8, "checkpoint_height", Normal),
                field!(9, "previous_checkpoint_hash", Hash32),
                field!(10, "state_root", Hash32),
                field!(11, "validator_id", Normal),
                field!(12, "validator_public_key", Key32),
                field!(13, "validator_key_era", Normal),
                field!(14, "signature", Signature64),
            ]
        ),
        "ConsensusStakeSlashEvidenceV1" => schema!(
            0x1036,
            "ConsensusStakeSlashEvidenceV1",
            [
                field!(1, "kind", Normal),
                field!(2, "first_vote", Normal, optional),
                field!(3, "second_vote", Normal, optional),
                field!(4, "first_checkpoint", Normal, optional),
                field!(5, "second_checkpoint", Normal, optional),
                field!(6, "proposal", Normal, optional),
                field!(7, "invalid_vote", Normal, optional),
            ]
        ),
        "SlashConsensusStakeV1" => schema!(
            0x1037,
            "SlashConsensusStakeV1",
            [
                field!(1, "slash_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "consensus_epoch", Normal),
                field!(11, "derived_epoch_record_hash", Hash32),
                field!(12, "position_id", Normal),
                field!(13, "escrow_coin_id", Normal),
                field!(14, "expected_position_amount", Amount),
                field!(15, "liability_commitment", Hash32),
                field!(16, "expected_unbond_request_commitment", Hash32, optional),
                field!(17, "evidence_hash", Hash32),
                field!(18, "evidence", Normal),
            ]
        ),
        "StakeStateResourcePolicyV1" => schema!(
            0x1038,
            "StakeStateResourcePolicyV1",
            [
                field!(1, "policy_version", Normal),
                field!(2, "sequence", Normal),
                field!(3, "previous_policy_commitment", Hash32),
                field!(4, "activation_delay_blocks", Normal),
                field!(5, "base_candidate_fee", Amount),
                field!(6, "base_position_fee", Amount),
                field!(7, "base_epoch_fee", Amount),
                field!(8, "base_unbond_fee", Amount),
                field!(9, "base_slash_evidence_fee", Amount),
                field!(10, "fee_per_wire_byte", Amount),
                field!(11, "fee_per_signature_verification", Amount),
                field!(12, "fee_per_state_read", Amount),
                field!(13, "fee_per_state_write", Amount),
                field!(14, "bond_per_persistent_byte", Amount),
                field!(15, "minimum_candidate_bond", Amount),
                field!(16, "minimum_position_bond", Amount),
                field!(17, "minimum_lease_blocks", Normal),
                field!(18, "maximum_lease_blocks", Normal),
                field!(19, "expiry_grace_blocks", Normal),
                field!(20, "terminal_retention_blocks", Normal),
                field!(21, "maximum_active_candidates", Normal),
                field!(22, "maximum_candidates_per_owner", Normal),
                field!(23, "maximum_active_positions", Normal),
                field!(24, "maximum_positions_per_owner", Normal),
                field!(25, "maximum_pending_unbonds", Normal),
                field!(26, "maximum_pending_unbonds_per_owner", Normal),
                field!(27, "maximum_slash_record_bytes", Normal),
                field!(28, "maximum_total_stake_state_bytes", Normal),
                field!(29, "maximum_stake_state_bytes_per_block", Normal),
                field!(30, "maximum_stake_signature_checks_per_block", Normal),
                field!(31, "maximum_stake_state_reads_per_block", Normal),
                field!(32, "maximum_stake_state_writes_per_block", Normal),
            ]
        ),
        "StakeStateResourceEnvelopeV1" => schema!(
            0x1039,
            "StakeStateResourceEnvelopeV1",
            [
                field!(1, "resource_policy_sequence", Normal),
                field!(2, "resource_policy_commitment", Hash32),
                field!(3, "sponsor", Normal),
                field!(4, "funding_coin_id", Normal),
                field!(5, "max_resource_fee", Amount),
                field!(6, "max_state_bond", Amount),
                field!(7, "lease_end_height", Normal),
                field!(8, "resource_subject_hash", Hash32),
                field!(9, "authorization", Normal),
            ]
        ),
        "StakeStateBondRecordV1" => schema!(
            0x103a,
            "StakeStateBondRecordV1",
            [
                field!(1, "bond_id", Normal),
                field!(2, "resource_key", Normal),
                field!(3, "resource_kind", Normal),
                field!(4, "sponsor", Normal),
                field!(5, "funding_source_coin_id", Normal),
                field!(6, "bond_coin_id", Normal),
                field!(7, "locked_amount", Amount),
                field!(8, "charged_creation_fee", Amount),
                field!(9, "charged_wire_bytes", Normal),
                field!(10, "charged_signature_checks", Normal),
                field!(11, "charged_state_reads", Normal),
                field!(12, "charged_state_writes", Normal),
                field!(13, "created_height", Normal),
                field!(14, "lease_end_height", Normal),
                field!(15, "forfeit_after_height", Normal),
                field!(16, "status", Normal),
                field!(17, "terminal_record_commitment", Hash32),
                field!(18, "record_hash", Hash32),
            ]
        ),
        "StakeStateMaintenancePoolV1" => schema!(
            0x103b,
            "StakeStateMaintenancePoolV1",
            [
                field!(1, "pool_version", Normal),
                field!(2, "resource_policy_sequence", Normal),
                field!(3, "resource_policy_commitment", Hash32),
                field!(4, "charged_fees", Amount),
                field!(5, "forfeited_bonds", Amount),
                field!(6, "live_bonds", Amount),
                field!(7, "refunded_bonds", Amount),
                field!(8, "active_bond_records", Normal),
                field!(9, "terminal_bond_records", Normal),
                field!(10, "previous_pool_commitment", Hash32),
                field!(11, "runtime_payout_enabled", Normal),
                field!(12, "pool_commitment", Hash32),
            ]
        ),
        "ProposeStakeStateResourcePolicyV1" => schema!(
            0x103c,
            "ProposeStakeStateResourcePolicyV1",
            [
                field!(1, "proposal_id", Normal),
                field!(2, "network_domain", Normal),
                field!(3, "zone_id", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "proposed_height", Normal),
                field!(8, "activate_after_height", Normal),
                field!(9, "expires_at_height", Normal),
                field!(10, "expected_current_policy_sequence", Normal),
                field!(11, "expected_current_policy_commitment", Hash32),
                field!(12, "proposed_policy", Normal),
                field!(13, "proposed_policy_commitment", Hash32),
                field!(14, "subject_hash", Hash32),
                field!(15, "validator_qc", Normal),
                field!(16, "notary_qc", Normal),
            ]
        ),
        "ActivateStakeStateResourcePolicyV1" => schema!(
            0x103d,
            "ActivateStakeStateResourcePolicyV1",
            [
                field!(1, "activation_id", Normal),
                field!(2, "network_domain", Normal),
                field!(3, "zone_id", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "proposed_height", Normal),
                field!(8, "expires_at_height", Normal),
                field!(9, "proposal_id", Normal),
                field!(10, "expected_pending_policy_commitment", Hash32),
                field!(11, "expected_current_policy_sequence", Normal),
                field!(12, "expected_current_policy_commitment", Hash32),
                field!(13, "subject_hash", Hash32),
                field!(14, "validator_qc", Normal),
                field!(15, "notary_qc", Normal),
            ]
        ),
        "StakeStateBondRecordV2" => schema!(
            0x103e,
            "StakeStateBondRecordV2",
            [
                field!(1, "bond_id", Normal),
                field!(2, "resource_key", Normal),
                field!(3, "resource_kind", Normal),
                field!(4, "resource_owner", Normal),
                field!(5, "resource_policy_sequence", Normal),
                field!(6, "resource_policy_commitment", Hash32),
                field!(7, "resource_subject_hash", Hash32),
                field!(8, "sponsor", Normal),
                field!(9, "sponsor_authorization_id", Normal),
                field!(10, "funding_source_coin_id", Normal),
                field!(11, "bond_coin_id", Normal),
                field!(12, "locked_amount", Amount),
                field!(13, "charged_creation_fee", Amount),
                field!(14, "charged_wire_bytes", Normal),
                field!(15, "charged_persistent_bytes", Normal),
                field!(16, "charged_signature_checks", Normal),
                field!(17, "charged_state_reads", Normal),
                field!(18, "charged_state_writes", Normal),
                field!(19, "created_height", Normal),
                field!(20, "lease_end_height", Normal),
                field!(21, "forfeit_after_height", Normal),
                field!(22, "status", Normal),
                field!(23, "terminal_record_commitment", Hash32),
                field!(24, "previous_record_hash", Hash32),
                field!(25, "record_hash", Hash32),
            ]
        ),
        "StakeStateMaintenancePoolPolicyBucketV2" => schema!(
            0x103f,
            "StakeStateMaintenancePoolPolicyBucketV2",
            [
                field!(1, "resource_policy_sequence", Normal),
                field!(2, "resource_policy_commitment", Hash32),
                field!(3, "charged_fees", Amount),
                field!(4, "forfeited_bonds", Amount),
                field!(5, "live_bonds", Amount),
                field!(6, "refunded_bonds", Amount),
                field!(7, "active_bond_records", Normal),
                field!(8, "terminal_bond_records", Normal),
                field!(9, "bucket_commitment", Hash32),
            ]
        ),
        "StakeStateMaintenancePoolV2" => schema!(
            0x1040,
            "StakeStateMaintenancePoolV2",
            [
                field!(1, "pool_version", Normal),
                field!(2, "policy_buckets", Normal),
                field!(3, "total_charged_fees", Amount),
                field!(4, "total_forfeited_bonds", Amount),
                field!(5, "total_live_bonds", Amount),
                field!(6, "total_refunded_bonds", Amount),
                field!(7, "active_bond_records", Normal),
                field!(8, "terminal_bond_records", Normal),
                field!(9, "previous_pool_commitment", Hash32),
                field!(10, "runtime_payout_enabled", Normal),
                field!(11, "pool_commitment", Hash32),
            ]
        ),
        "RegisterConsensusValidatorRequestV2" => schema!(
            0x1041,
            "RegisterConsensusValidatorRequestV2",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "validator_id", Normal),
                field!(11, "owner", Normal),
                field!(12, "public_key", Key32),
                field!(13, "key_era", Normal),
                field!(14, "proof_of_possession", Signature64),
                field!(15, "resource_envelope", Normal),
                field!(16, "authorization", Normal),
            ]
        ),
        "LockConsensusStakeRequestV3" => schema!(
            0x1042,
            "LockConsensusStakeRequestV3",
            [
                field!(1, "position_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_type", Normal),
                field!(11, "validator_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "source_coin_id", Normal),
                field!(14, "amount", Amount),
                field!(15, "committed_through_height", Normal),
                field!(16, "slash_terms_authorization", Normal),
                field!(17, "resource_envelope", Normal),
                field!(18, "authorization", Normal),
            ]
        ),
        "MigrateConsensusStakeResourceRequestV1" => schema!(
            0x1043,
            "MigrateConsensusStakeResourceRequestV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_id", Normal),
                field!(11, "escrow_coin_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "expected_position_commitment", Hash32),
                field!(14, "resource_envelope", Normal),
                field!(15, "authorization", Normal),
            ]
        ),
        "MigrateConsensusCandidateResourceRequestV1" => schema!(
            0x1044,
            "MigrateConsensusCandidateResourceRequestV1",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "validator_id", Normal),
                field!(11, "owner", Normal),
                field!(12, "public_key", Key32),
                field!(13, "key_era", Normal),
                field!(14, "registered_height", Normal),
                field!(15, "exit_height", Normal, optional),
                field!(16, "proof_of_possession", Signature64),
                field!(17, "expected_candidate_commitment", Hash32),
                field!(18, "resource_envelope", Normal),
                field!(19, "authorization", Normal),
            ]
        ),
        "DeriveNextStakeEpochRequestV2" => schema!(
            0x1045,
            "DeriveNextStakeEpochRequestV2",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "expected_consensus_epoch", Normal),
                field!(11, "expected_snapshot_height", Normal),
                field!(12, "expected_snapshot_state_root", Hash32),
                field!(13, "expected_derived_record_hash", Hash32),
                field!(14, "payer", Normal),
                field!(15, "resource_envelope", Normal),
                field!(16, "authorization", Normal),
            ]
        ),
        "RenewStakeStateResourceBondRequestV1" => schema!(
            0x1046,
            "RenewStakeStateResourceBondRequestV1",
            [
                field!(1, "renewal_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "resource_key", Normal),
                field!(9, "resource_kind", Normal),
                field!(10, "resource_owner", Normal),
                field!(11, "expected_bond_id", Hash32),
                field!(12, "expected_initial_bond_record_hash", Hash32),
                field!(13, "expected_previous_renewal_hash", Hash32),
                field!(14, "expected_current_lease_end_height", Normal),
                field!(15, "new_lease_end_height", Normal),
                field!(16, "resource_policy_sequence", Normal),
                field!(17, "resource_policy_commitment", Hash32),
                field!(18, "sponsor", Normal),
                field!(19, "funding_coin_id", Normal),
                field!(20, "max_resource_fee", Amount),
                field!(21, "max_additional_bond", Amount),
                field!(22, "authorization", Normal),
            ]
        ),
        "StakeStateBondRenewalRecordV1" => schema!(
            0x1047,
            "StakeStateBondRenewalRecordV1",
            [
                field!(1, "renewal_id", Normal),
                field!(2, "resource_key", Normal),
                field!(3, "resource_kind", Normal),
                field!(4, "resource_owner", Normal),
                field!(5, "original_bond_id", Hash32),
                field!(6, "initial_bond_record_hash", Hash32),
                field!(7, "previous_renewal_hash", Hash32),
                field!(8, "previous_lease_end_height", Normal),
                field!(9, "new_lease_end_height", Normal),
                field!(10, "resource_policy_sequence", Normal),
                field!(11, "resource_policy_commitment", Hash32),
                field!(12, "sponsor", Normal),
                field!(13, "sponsor_authorization_id", Normal),
                field!(14, "funding_source_coin_id", Normal),
                field!(15, "bond_coin_id", Normal),
                field!(16, "additional_locked_amount", Amount),
                field!(17, "charged_renewal_fee", Amount),
                field!(18, "charged_wire_bytes", Normal),
                field!(19, "charged_persistent_bytes", Normal),
                field!(20, "charged_signature_checks", Normal),
                field!(21, "charged_state_reads", Normal),
                field!(22, "charged_state_writes", Normal),
                field!(23, "renewed_height", Normal),
                field!(24, "forfeit_after_height", Normal),
                field!(25, "record_hash", Hash32),
            ]
        ),
        "RequestConsensusStakeUnbondV2" => schema!(
            0x1060,
            "RequestConsensusStakeUnbondV2",
            [
                field!(1, "request_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "proposed_height", Normal),
                field!(7, "expires_at_height", Normal),
                field!(8, "expected_authority_sequence", Normal),
                field!(9, "expected_authority_commitment", Hash32),
                field!(10, "position_id", Normal),
                field!(11, "escrow_coin_id", Normal),
                field!(12, "owner", Normal),
                field!(13, "beneficiary", Normal),
                field!(14, "requested_withdraw_after_height", Normal),
                field!(15, "expected_position_commitment", Hash32),
                field!(16, "expected_liability_horizon_commitment", Hash32),
                field!(17, "expected_position_resource_bond_record_hash", Hash32),
                field!(18, "resource_envelope", Normal),
                field!(19, "authorization", Normal),
            ]
        ),
        "CompleteConsensusStakeUnbondV2" => schema!(
            0x1061,
            "CompleteConsensusStakeUnbondV2",
            [
                field!(1, "completion_id", Normal),
                field!(2, "request_id", Normal),
                field!(3, "zone_id", Normal),
                field!(4, "currency_genesis_root", Hash32),
                field!(5, "protocol_era", Normal),
                field!(6, "crypto_era", Normal),
                field!(7, "proposed_height", Normal),
                field!(8, "expires_at_height", Normal),
                field!(9, "expected_unbond_request_commitment", Hash32),
                field!(10, "beneficiary", Normal),
                field!(11, "expected_unbond_resource_bond_record_hash", Hash32),
                field!(12, "expected_position_resource_bond_record_hash", Hash32),
                field!(13, "expected_liability_horizon_commitment", Hash32),
                field!(14, "resource_mutation_envelope", Normal),
            ]
        ),
        "StakeStateResourceMutationEnvelopeV1" => schema!(
            0x1062,
            "StakeStateResourceMutationEnvelopeV1",
            [
                field!(1, "resource_policy_sequence", Normal),
                field!(2, "resource_policy_commitment", Hash32),
                field!(3, "sponsor", Normal),
                field!(4, "funding_coin_id", Normal),
                field!(5, "max_resource_fee", Amount),
                field!(6, "outer_operation_hash", Hash32),
                field!(7, "expected_mutated_bond_record_hash", Hash32),
                field!(8, "resource_subject_hash", Hash32),
                field!(9, "authorization", Normal),
            ]
        ),
        "StakePositionLiabilityHorizonV1" => schema!(
            0x1063,
            "StakePositionLiabilityHorizonV1",
            [
                field!(1, "horizon_version", Normal),
                field!(2, "position_id", Normal),
                field!(3, "owner", Normal),
                field!(4, "escrow_coin_id", Normal),
                field!(5, "retained_liability_count", Normal),
                field!(6, "max_evidence_deadline_height", Normal),
                field!(7, "last_consensus_epoch", Normal),
                field!(8, "liability_accumulator_root", Hash32),
                field!(9, "previous_horizon_commitment", Hash32),
                field!(10, "horizon_commitment", Hash32),
            ]
        ),

        "ConsensusCommand::ExportPayment" => schema!(
            0x2001,
            "ConsensusCommand::ExportPayment",
            [field!(1, "intent", Normal), field!(2, "transport", Normal),]
        ),
        "ProductionCommand::RouteQuoteReroute" => schema!(
            0x2103,
            "ProductionCommand::RouteQuoteReroute",
            [field!(1, "quote_id", Normal), field!(2, "request", Normal),]
        ),
        "ProductionCommand::RejectionCreate" => schema!(
            0x2107,
            "ProductionCommand::RejectionCreate",
            [field!(1, "capsule", Normal), field!(2, "reason", Normal),]
        ),
        "ProductionCommand::RejectionCertify" => schema!(
            0x2108,
            "ProductionCommand::RejectionCertify",
            [
                field!(1, "transit_id", Normal),
                field!(2, "validator_qc", Normal),
                field!(3, "notary_qc", Normal),
            ]
        ),
        "ProductionCommand::TransitCertify" => schema!(
            0x210b,
            "ProductionCommand::TransitCertify",
            [
                field!(1, "transit_id", Normal),
                field!(2, "validator_qc", Normal),
                field!(3, "notary_qc", Normal),
            ]
        ),
        "ProductionCommand::TravelerCreate" => schema!(
            0x210c,
            "ProductionCommand::TravelerCreate",
            [field!(1, "intent", Normal), field!(2, "transport", Normal),]
        ),
        "ProductionCommand::ServiceOrder" => schema!(
            0x2112,
            "ProductionCommand::ServiceOrder",
            [
                field!(1, "buyer", Normal),
                field!(2, "coin_id", Normal),
                field!(3, "role", Normal),
                field!(4, "budget", Amount),
                field!(5, "description", Normal),
                field!(6, "authorization", Normal),
            ]
        ),
        "ProductionCommand::ServiceLease" => schema!(
            0x2113,
            "ProductionCommand::ServiceLease",
            [
                field!(1, "order_id", Normal),
                field!(2, "node_id", Normal),
                field!(3, "accepted_quote", Amount),
                field!(4, "authorization", Normal),
            ]
        ),
        "ProductionCommand::ServiceComplete" => schema!(
            0x2114,
            "ProductionCommand::ServiceComplete",
            [
                field!(1, "lease_id", Normal),
                field!(2, "proof_hash", Hash32),
                field!(3, "authorization", Normal),
                field!(4, "validator_qc", Normal),
                field!(5, "notary_qc", Normal),
            ]
        ),
        "ProductionCommand::ProtocolServiceBondUnbond" => schema!(
            0x211a,
            "ProductionCommand::ProtocolServiceBondUnbond",
            [
                field!(1, "bond_id", Normal),
                field!(2, "authorization", Normal),
            ]
        ),
        "ProductionCommand::VoyageOpen" => schema!(
            0x211c,
            "ProductionCommand::VoyageOpen",
            [
                field!(1, "payer", Normal),
                field!(2, "coin_id", Normal),
                field!(3, "transit_id", Normal),
                field!(4, "budget", Amount),
                field!(5, "max_reward_per_hop", Amount),
                field!(6, "authorization", Normal),
            ]
        ),
        "ProductionCommand::VoyageSettle" => schema!(
            0x211d,
            "ProductionCommand::VoyageSettle",
            [
                field!(1, "escrow_id", Normal),
                field!(2, "node_id", Normal),
                field!(3, "amount", Amount),
                field!(4, "downstream_receipt_hash", Hash32),
                field!(5, "authorization", Normal),
            ]
        ),
        "NetworkHeartbeatV1" => schema!(
            0x1070,
            "NetworkHeartbeatV1",
            [
                field!(1, "heartbeat_id", Normal),
                field!(2, "zone_id", Normal),
                field!(3, "currency_genesis_root", Hash32),
                field!(4, "protocol_era", Normal),
                field!(5, "crypto_era", Normal),
                field!(6, "parent_height", Normal),
                field!(7, "note_hash", Hash32),
            ]
        ),
        _ => return None,
    })
}

fn enum_variant_tag(name: &str, variant: &str) -> Option<(u16, u16)> {
    let (id, variants): (u16, &[&str]) = match name {
        "ValueCap" => (
            0x3001,
            &["VALUE_CAP_0", "VALUE_CAP_1", "VALUE_CAP_2", "VALUE_CAP_3"],
        ),
        "TransportClass" => (
            0x3002,
            &[
                "SUBLIGHT_DTN",
                "CAUSAL_FTL",
                "CAUSAL_WORMHOLE",
                "CHRONOLOGY_UNSAFE",
            ],
        ),
        "CoinState" => (
            0x3003,
            &[
                "SPENDABLE",
                "RESERVED",
                "IN_TRANSIT",
                "RETURNING",
                "QUARANTINED",
                "CONSUMED",
            ],
        ),
        "DestinationRejectionReason" => (
            0x3004,
            &[
                "RECIPIENT_DECLINED",
                "POLICY_REJECTED",
                "PROTOCOL_UNSUPPORTED",
                "ROUTE_UNAVAILABLE",
                "INVALID_COMMERCIAL_REQUEST",
            ],
        ),
        "ServiceRole" => (
            0x3005,
            &[
                "VALIDATOR",
                "NOTARY",
                "RELAY",
                "STORAGE",
                "ARCHIVE",
                "GATEWAY",
                "LIQUIDITY",
                "CONTINUITY_CUSTODIAN",
                "FTL_GATEWAY",
                "OBSERVER",
            ],
        ),
        "ProtocolReservePoolKind" => (
            0x3006,
            &["STARTUP_SERVICES", "CONTINUITY_SERVICES", "DEMAND_MATCHING"],
        ),
        "EconomicControlRole" => (
            0x3007,
            &[
                "REQUESTER",
                "SERVICE_PROVIDER",
                "RELAY",
                "LIQUIDITY_PROVIDER",
                "VALIDATOR",
                "NOTARY",
                "PRICE_SOURCE",
            ],
        ),
        "StakePositionTypeV1" => (0x3008, &["SELF_BOND", "DELEGATION"]),
        "ConsensusStakeSlashEvidenceKindV1" => (
            0x3009,
            &[
                "DOUBLE_SIGN",
                "CONFLICTING_CHECKPOINT",
                "INVALID_STATE_COMMITMENT",
            ],
        ),
        "StakeStateResourceKindV1" => (
            0x300a,
            &["CANDIDATE", "POSITION", "EPOCH", "UNBOND", "SLASH_EVIDENCE"],
        ),
        "StakeStateBondStatusV1" => (0x300b, &["LOCKED", "RELEASEABLE", "REFUNDED", "FORFEITED"]),
        _ => return None,
    };
    variants
        .iter()
        .position(|candidate| *candidate == variant)
        .and_then(|index| u16::try_from(index + 1).ok())
        .map(|tag| (id, tag))
}

#[derive(Clone)]
enum Node {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    String(String),
    Unit,
    Option(Option<Box<Node>>),
    Seq(Vec<Node>),
    Struct {
        name: &'static str,
        fields: Vec<(&'static str, Node)>,
    },
    UnitEnum {
        name: &'static str,
        variant: &'static str,
    },
    Bytes(Vec<u8>),
}

#[derive(Debug)]
struct CommandSerializeError(String);

impl fmt::Display for CommandSerializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for CommandSerializeError {}
impl serde::ser::Error for CommandSerializeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

struct CommandSerializer;

impl Serializer for CommandSerializer {
    type Ok = Node;
    type Error = CommandSerializeError;
    type SerializeSeq = SequenceSerializer;
    type SerializeTuple = Impossible<Node, CommandSerializeError>;
    type SerializeTupleStruct = Impossible<Node, CommandSerializeError>;
    type SerializeTupleVariant = Impossible<Node, CommandSerializeError>;
    type SerializeMap = Impossible<Node, CommandSerializeError>;
    type SerializeStruct = StructSerializer;
    type SerializeStructVariant = Impossible<Node, CommandSerializeError>;

    fn serialize_bool(self, value: bool) -> Result<Node, Self::Error> {
        Ok(Node::Bool(value))
    }
    fn serialize_u8(self, value: u8) -> Result<Node, Self::Error> {
        Ok(Node::U8(value))
    }
    fn serialize_u16(self, value: u16) -> Result<Node, Self::Error> {
        Ok(Node::U16(value))
    }
    fn serialize_u32(self, value: u32) -> Result<Node, Self::Error> {
        Ok(Node::U32(value))
    }
    fn serialize_u64(self, value: u64) -> Result<Node, Self::Error> {
        Ok(Node::U64(value))
    }
    fn serialize_u128(self, value: u128) -> Result<Node, Self::Error> {
        Ok(Node::U128(value))
    }
    fn serialize_str(self, value: &str) -> Result<Node, Self::Error> {
        Ok(Node::String(value.to_owned()))
    }
    fn serialize_char(self, value: char) -> Result<Node, Self::Error> {
        self.serialize_str(&value.to_string())
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<Node, Self::Error> {
        Ok(Node::Bytes(value.to_vec()))
    }
    fn serialize_none(self) -> Result<Node, Self::Error> {
        Ok(Node::Option(None))
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Node, Self::Error> {
        Ok(Node::Option(Some(Box::new(value.serialize(Self)?))))
    }
    fn serialize_unit(self) -> Result<Node, Self::Error> {
        Ok(Node::Unit)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Node, Self::Error> {
        Ok(Node::Unit)
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Node, Self::Error> {
        if enum_variant_tag(name, variant).is_none() {
            return Err(CommandSerializeError(format!(
                "unregistered command enum variant {name}::{variant}"
            )));
        }
        Ok(Node::UnitEnum { name, variant })
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Node, Self::Error> {
        value.serialize(self)
    }
    fn serialize_seq(self, length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SequenceSerializer {
            values: Vec::with_capacity(length.unwrap_or(0)),
        })
    }
    fn serialize_struct(
        self,
        name: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        if struct_schema(name).is_none() {
            return Err(CommandSerializeError(format!(
                "unregistered command struct {name}"
            )));
        }
        Ok(StructSerializer {
            name,
            fields: Vec::with_capacity(length),
        })
    }

    fn serialize_i8(self, _value: i8) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_i16(self, _value: i16) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_i32(self, _value: i32) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_i64(self, _value: i64) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_i128(self, _value: i128) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_f32(self, _value: f32) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_f64(self, _value: f64) -> Result<Node, Self::Error> {
        Err(forbidden_number())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Node, Self::Error> {
        Err(unsupported_shape("newtype enum variant"))
    }
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(unsupported_shape("tuple"))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(unsupported_shape("tuple struct"))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(unsupported_shape("tuple enum variant"))
    }
    fn serialize_map(self, _length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(unsupported_shape("map"))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(unsupported_shape("struct enum variant"))
    }
}

fn forbidden_number() -> CommandSerializeError {
    CommandSerializeError(
        "signed integers and floating point are forbidden in command payloads".into(),
    )
}
fn unsupported_shape(shape: &str) -> CommandSerializeError {
    CommandSerializeError(format!("unregistered command serialization shape: {shape}"))
}

struct SequenceSerializer {
    values: Vec<Node>,
}
impl SerializeSeq for SequenceSerializer {
    type Ok = Node;
    type Error = CommandSerializeError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.values.push(value.serialize(CommandSerializer)?);
        Ok(())
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Seq(self.values))
    }
}

struct StructSerializer {
    name: &'static str,
    fields: Vec<(&'static str, Node)>,
}
impl SerializeStruct for StructSerializer {
    type Ok = Node;
    type Error = CommandSerializeError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        let schema = struct_schema(self.name).ok_or_else(|| {
            CommandSerializeError(format!("unregistered command struct {}", self.name))
        })?;
        if !schema.fields.iter().any(|field| field.name == key) {
            return Err(CommandSerializeError(format!(
                "unregistered command field {}.{key}",
                self.name
            )));
        }
        self.fields.push((key, value.serialize(CommandSerializer)?));
        Ok(())
    }
    fn end(self) -> Result<Node, Self::Error> {
        Ok(Node::Struct {
            name: self.name,
            fields: self.fields,
        })
    }
}

fn node<T: ?Sized + Serialize>(value: &T) -> Result<Node, WireError> {
    value
        .serialize(CommandSerializer)
        .map_err(|error| WireError::new("unsupported_command_schema", error.to_string()))
}
fn fields(name: &'static str, values: Vec<(&'static str, Node)>) -> Node {
    Node::Struct {
        name,
        fields: values,
    }
}

/// Encodes one explicitly registered candidate payload without admitting a
/// new runtime `ConsensusCommand` variant. R6.15 uses this only for frozen
/// codec vectors; ledger and node dispatch never call it.
pub(crate) fn encode_codec_only_candidate_payload<T: ?Sized + Serialize>(
    value: &T,
) -> Result<Vec<u8>, WireError> {
    let root = node(value)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(PAYLOAD_MAGIC);
    payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    encode_node(&root, Semantic::Normal, &mut payload)?;
    Ok(payload)
}

/// Encodes the formal tag-28 payload. The payload contains one bytes node
/// whose value is the proof's canonical RLD-WIRE schema-0x1071 object. This
/// function is shared by `ConsensusCommand` and the frozen pre-adoption
/// vectors, so formal adoption cannot silently change those bytes.
pub fn encode_admission_checkpoint_payload_v1(
    proof: &AdmissionCheckpointProofV1,
) -> Result<Vec<u8>, WireError> {
    let proof_wire = proof
        .canonical_bytes()
        .map_err(|error| WireError::new("invalid_admission_checkpoint_proof", error.to_string()))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(PAYLOAD_MAGIC);
    payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    encode_node(&Node::Bytes(proof_wire), Semantic::Normal, &mut payload)?;
    Ok(payload)
}

/// Backward-compatible vector builder retained for the frozen R7.2 artifact.
pub fn encode_admission_checkpoint_candidate_payload_v1(
    proof: &AdmissionCheckpointProofV1,
) -> Result<Vec<u8>, WireError> {
    encode_admission_checkpoint_payload_v1(proof)
}

pub fn encode_admission_checkpoint_candidate_command_v1(
    network_domain: &str,
    proof: &AdmissionCheckpointProofV1,
) -> Result<Vec<u8>, WireError> {
    encode_reserved_command_commitment_candidate(
        network_domain,
        28,
        &encode_admission_checkpoint_payload_v1(proof)?,
    )
}

pub fn admission_checkpoint_candidate_command_hash_v1(
    network_domain: &str,
    proof: &AdmissionCheckpointProofV1,
) -> Result<String, WireError> {
    let wire = encode_admission_checkpoint_candidate_command_v1(network_domain, proof)?;
    Ok(digest_hex(WireSchema::CommandCommitment, &wire))
}

impl ConsensusCommand {
    pub fn wire_v1_command_payload_bytes(&self) -> Result<Vec<u8>, WireError> {
        if matches!(self, Self::ActivatePendingValueRiskPolicy) {
            return Ok(Vec::new());
        }
        if let Self::ScheduleUpgrade(schedule) = self {
            let raw = schedule
                .canonical_bytes()
                .map_err(|e| WireError::new("invalid_upgrade_schedule", e))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(PAYLOAD_MAGIC);
            payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
            encode_node(&Node::Bytes(raw), Semantic::Normal, &mut payload)?;
            return Ok(payload);
        }
        if let Self::ActivateUpgrade(activation) = self {
            let raw = activation
                .canonical_bytes()
                .map_err(|e| WireError::new("invalid_upgrade_activation", e))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(PAYLOAD_MAGIC);
            payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
            encode_node(&Node::Bytes(raw), Semantic::Normal, &mut payload)?;
            return Ok(payload);
        }
        if let Self::CommitAdmissionCheckpoint(proof) = self {
            return encode_admission_checkpoint_payload_v1(proof);
        }
        let root = match self {
            Self::LocalPayment(intent) => node(intent)?,
            Self::ExportPayment { intent, transport } => fields(
                "ConsensusCommand::ExportPayment",
                vec![("intent", node(intent)?), ("transport", node(transport)?)],
            ),
            Self::ImportCapsule(capsule) => node(capsule)?,
            Self::FinalizeExport(receipt) => node(receipt)?,
            Self::SubmitValueRiskPolicyUpdate(update) => node(update)?,
            Self::Production(command) => command.wire_v1_payload_node()?,
            Self::SubmitStakeAuthorityUpdate(update) => node(update)?,
            Self::DeriveNextStakeEpoch(request) => node(request)?,
            Self::LockConsensusStake(request) => node(request)?,
            Self::RegisterConsensusValidator(request) => node(request)?,
            Self::RegisterConsensusValidatorV2(request) => node(request)?,
            Self::ExitConsensusValidator(request) => node(request)?,
            Self::RequestConsensusStakeUnbond(request) => node(request)?,
            Self::CompleteConsensusStakeUnbond(request) => node(request)?,
            Self::LockConsensusStakeV2(request) => node(request)?,
            Self::MigrateConsensusStakeSlashTerms(request) => node(request)?,
            Self::SlashConsensusStake(request) => node(request)?,
            Self::ProposeStakeStateResourcePolicy(request) => node(request)?,
            Self::ActivateStakeStateResourcePolicy(request) => node(request)?,
            Self::LockConsensusStakeV3(request) => node(request)?,
            Self::MigrateConsensusStakeResource(request) => node(request)?,
            Self::MigrateConsensusCandidateResource(request) => node(request)?,
            Self::DeriveNextStakeEpochV2(request) => node(request)?,
            Self::RenewStakeStateResourceBond(request) => node(request)?,
            Self::CommitAdmissionCheckpoint(_)
            | Self::ScheduleUpgrade(_)
            | Self::ActivateUpgrade(_) => unreachable!(),
            Self::NetworkHeartbeat(heartbeat) => node(heartbeat)?,
            Self::ActivatePendingValueRiskPolicy => unreachable!(),
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(PAYLOAD_MAGIC);
        payload.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        encode_node(&root, Semantic::Normal, &mut payload)?;
        Ok(payload)
    }

    pub fn wire_v1_command_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        if let Self::ActivateUpgrade(activation) = self {
            if activation.network_domain != network_domain {
                return Err(WireError::new(
                    "upgrade_network_mismatch",
                    "activation and outer network differ",
                ));
            }
        }
        if let Self::ScheduleUpgrade(schedule) = self {
            if schedule.network_domain != network_domain {
                return Err(WireError::new(
                    "upgrade_network_mismatch",
                    "schedule and outer network differ",
                ));
            }
        }
        let payload = self.wire_v1_command_payload_bytes()?;
        let production_tag = match self {
            Self::Production(command) => Some(command.wire_v1_tag()),
            _ => None,
        };
        encode_command_commitment(network_domain, self.wire_v1_tag(), production_tag, &payload)
    }
    pub fn wire_v1_command_hash(&self, network_domain: &str) -> Result<String, WireError> {
        let wire = self.wire_v1_command_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::CommandCommitment, &wire))
    }
    pub const fn wire_v1_tag(&self) -> u16 {
        match self {
            Self::LocalPayment(_) => 1,
            Self::ExportPayment { .. } => 2,
            Self::ImportCapsule(_) => 3,
            Self::FinalizeExport(_) => 4,
            Self::SubmitValueRiskPolicyUpdate(_) => 5,
            Self::ActivatePendingValueRiskPolicy => 6,
            Self::Production(_) => 7,
            Self::SubmitStakeAuthorityUpdate(_) => 8,
            Self::DeriveNextStakeEpoch(_) => 9,
            Self::LockConsensusStake(_) => 10,
            Self::RegisterConsensusValidator(_) => 11,
            Self::ExitConsensusValidator(_) => 12,
            Self::RequestConsensusStakeUnbond(_) => 13,
            Self::CompleteConsensusStakeUnbond(_) => 14,
            Self::LockConsensusStakeV2(_) => 15,
            Self::MigrateConsensusStakeSlashTerms(_) => 16,
            Self::SlashConsensusStake(_) => 17,
            Self::ProposeStakeStateResourcePolicy(_) => 18,
            Self::ActivateStakeStateResourcePolicy(_) => 19,
            Self::RegisterConsensusValidatorV2(_) => 20,
            Self::LockConsensusStakeV3(_) => 21,
            Self::MigrateConsensusStakeResource(_) => 22,
            Self::MigrateConsensusCandidateResource(_) => 23,
            Self::DeriveNextStakeEpochV2(_) => 24,
            Self::RenewStakeStateResourceBond(_) => 25,
            Self::CommitAdmissionCheckpoint(_) => 28,
            Self::NetworkHeartbeat(_) => 36,
            Self::ScheduleUpgrade(_) => 37,
            Self::ActivateUpgrade(_) => 38,
        }
    }
}

impl ProductionCommand {
    fn wire_v1_payload_node(&self) -> Result<Node, WireError> {
        Ok(match self {
            Self::ZoneAdvertisement(value) => node(value)?,
            Self::RouteQuoteCreate(value) => node(value)?,
            Self::RouteQuoteReroute { quote_id, request } => fields(
                "ProductionCommand::RouteQuoteReroute",
                vec![("quote_id", node(quote_id)?), ("request", node(request)?)],
            ),
            Self::PaymentRequest(value) => node(value)?,
            Self::RecipientReceipt(value) => node(value)?,
            Self::GatewayBond(value) => node(value)?,
            Self::RejectionCreate { capsule, reason } => fields(
                "ProductionCommand::RejectionCreate",
                vec![("capsule", node(capsule)?), ("reason", node(reason)?)],
            ),
            Self::RejectionCertify {
                transit_id,
                validator_qc,
                notary_qc,
            } => fields(
                "ProductionCommand::RejectionCertify",
                vec![
                    ("transit_id", node(transit_id)?),
                    ("validator_qc", node(validator_qc)?),
                    ("notary_qc", node(notary_qc)?),
                ],
            ),
            Self::ReturnBegin(value) => node(value)?,
            Self::ReturnFinalize(value) => node(value)?,
            Self::TransitCertify {
                transit_id,
                validator_qc,
                notary_qc,
            } => fields(
                "ProductionCommand::TransitCertify",
                vec![
                    ("transit_id", node(transit_id)?),
                    ("validator_qc", node(validator_qc)?),
                    ("notary_qc", node(notary_qc)?),
                ],
            ),
            Self::TravelerCreate { intent, transport } => fields(
                "ProductionCommand::TravelerCreate",
                vec![("intent", node(intent)?), ("transport", node(transport)?)],
            ),
            Self::TravelerImport(value) => node(value)?,
            Self::DscIssue(value) => node(value)?,
            Self::LiquidityOfferCreate(value) => node(value)?,
            Self::LiquidityOfferTake(value) => node(value)?,
            Self::ProtocolServiceOrder(value) => node(value)?,
            Self::ServiceOrder {
                buyer,
                coin_id,
                role,
                budget,
                description,
                authorization,
            } => fields(
                "ProductionCommand::ServiceOrder",
                vec![
                    ("buyer", node(buyer)?),
                    ("coin_id", node(coin_id)?),
                    ("role", node(role)?),
                    ("budget", node(budget)?),
                    ("description", node(description)?),
                    ("authorization", node(authorization)?),
                ],
            ),
            Self::ServiceLease {
                order_id,
                node_id,
                accepted_quote,
                authorization,
            } => fields(
                "ProductionCommand::ServiceLease",
                vec![
                    ("order_id", node(order_id)?),
                    ("node_id", node(node_id)?),
                    ("accepted_quote", node(accepted_quote)?),
                    ("authorization", node(authorization)?),
                ],
            ),
            Self::ServiceComplete {
                lease_id,
                proof_hash,
                authorization,
                validator_qc,
                notary_qc,
            } => fields(
                "ProductionCommand::ServiceComplete",
                vec![
                    ("lease_id", node(lease_id)?),
                    ("proof_hash", node(proof_hash)?),
                    ("authorization", node(authorization)?),
                    ("validator_qc", node(validator_qc)?),
                    ("notary_qc", node(notary_qc)?),
                ],
            ),
            Self::EconomicControlAttestation(value) => node(value)?,
            Self::EconomicPriceAttestation(value) => node(value)?,
            Self::EconomicReleasePolicy(value) => node(value)?,
            Self::ProtocolServiceBondLock(value) => node(value)?,
            Self::ProtocolServiceBondSlash(value) => node(value)?,
            Self::ProtocolServiceBondUnbond {
                bond_id,
                authorization,
            } => fields(
                "ProductionCommand::ProtocolServiceBondUnbond",
                vec![
                    ("bond_id", node(bond_id)?),
                    ("authorization", node(authorization)?),
                ],
            ),
            Self::ProtocolReserveRelease(value) => node(value)?,
            Self::VoyageOpen {
                payer,
                coin_id,
                transit_id,
                budget,
                max_reward_per_hop,
                authorization,
            } => fields(
                "ProductionCommand::VoyageOpen",
                vec![
                    ("payer", node(payer)?),
                    ("coin_id", node(coin_id)?),
                    ("transit_id", node(transit_id)?),
                    ("budget", node(budget)?),
                    ("max_reward_per_hop", node(max_reward_per_hop)?),
                    ("authorization", node(authorization)?),
                ],
            ),
            Self::VoyageSettle {
                escrow_id,
                node_id,
                amount,
                downstream_receipt_hash,
                authorization,
            } => fields(
                "ProductionCommand::VoyageSettle",
                vec![
                    ("escrow_id", node(escrow_id)?),
                    ("node_id", node(node_id)?),
                    ("amount", node(amount)?),
                    ("downstream_receipt_hash", node(downstream_receipt_hash)?),
                    ("authorization", node(authorization)?),
                ],
            ),
            Self::EraTransition(value) => node(value)?,
        })
    }

    pub const fn wire_v1_tag(&self) -> u16 {
        match self {
            Self::ZoneAdvertisement(_) => 1,
            Self::RouteQuoteCreate(_) => 2,
            Self::RouteQuoteReroute { .. } => 3,
            Self::PaymentRequest(_) => 4,
            Self::RecipientReceipt(_) => 5,
            Self::GatewayBond(_) => 6,
            Self::RejectionCreate { .. } => 7,
            Self::RejectionCertify { .. } => 8,
            Self::ReturnBegin(_) => 9,
            Self::ReturnFinalize(_) => 10,
            Self::TransitCertify { .. } => 11,
            Self::TravelerCreate { .. } => 12,
            Self::TravelerImport(_) => 13,
            Self::DscIssue(_) => 14,
            Self::LiquidityOfferCreate(_) => 15,
            Self::LiquidityOfferTake(_) => 16,
            Self::ProtocolServiceOrder(_) => 17,
            Self::ServiceOrder { .. } => 18,
            Self::ServiceLease { .. } => 19,
            Self::ServiceComplete { .. } => 20,
            Self::EconomicControlAttestation(_) => 21,
            Self::EconomicPriceAttestation(_) => 22,
            Self::EconomicReleasePolicy(_) => 23,
            Self::ProtocolServiceBondLock(_) => 24,
            Self::ProtocolServiceBondSlash(_) => 25,
            Self::ProtocolServiceBondUnbond { .. } => 26,
            Self::ProtocolReserveRelease(_) => 27,
            Self::VoyageOpen { .. } => 28,
            Self::VoyageSettle { .. } => 29,
            Self::EraTransition(_) => 30,
        }
    }
}

fn encode_node(value: &Node, semantic: Semantic, out: &mut Vec<u8>) -> Result<(), WireError> {
    match value {
        Node::Bool(false) => out.push(0x01),
        Node::Bool(true) => out.push(0x02),
        Node::U8(value) => {
            out.push(0x10);
            out.push(*value);
        }
        Node::U16(value) => {
            out.push(0x11);
            out.extend_from_slice(&value.to_be_bytes());
        }
        Node::U32(value) => {
            out.push(0x12);
            out.extend_from_slice(&value.to_be_bytes());
        }
        Node::U64(value) => {
            out.push(0x13);
            out.extend_from_slice(&value.to_be_bytes());
        }
        Node::U128(value) => {
            out.push(0x14);
            out.extend_from_slice(&value.to_be_bytes());
        }
        Node::String(value) => encode_string(value, semantic, out)?,
        Node::Unit => out.push(0x30),
        Node::Option(None) => out.push(0x31),
        Node::Option(Some(value)) => {
            out.push(0x32);
            encode_framed(value, semantic, out)?;
        }
        Node::Seq(values) => {
            out.push(0x40);
            put_u32(out, values.len())?;
            if matches!(semantic, Semantic::CanonicalSet) {
                let mut encoded = values
                    .iter()
                    .map(|value| {
                        let mut bytes = Vec::new();
                        encode_node(value, Semantic::Normal, &mut bytes)?;
                        Ok(bytes)
                    })
                    .collect::<Result<Vec<_>, WireError>>()?;
                encoded.sort();
                if encoded.windows(2).any(|items| items[0] == items[1]) {
                    return Err(WireError::new(
                        "duplicate_command_set_item",
                        "command set contains duplicate items",
                    ));
                }
                for bytes in encoded {
                    put_u32(out, bytes.len())?;
                    out.extend_from_slice(&bytes);
                }
            } else {
                for value in values {
                    encode_framed(value, semantic, out)?;
                }
            }
        }
        Node::Struct { name, fields } => encode_struct(name, fields, out)?,
        Node::UnitEnum { name, variant } => {
            let (enum_id, variant_tag) = enum_variant_tag(name, variant).ok_or_else(|| {
                WireError::new(
                    "unsupported_command_schema",
                    format!("unregistered command enum variant {name}::{variant}"),
                )
            })?;
            out.push(0x50);
            out.extend_from_slice(&enum_id.to_be_bytes());
            out.extend_from_slice(&variant_tag.to_be_bytes());
        }
        Node::Bytes(value) => {
            out.push(0x42);
            put_u32(out, value.len())?;
            out.extend_from_slice(value);
        }
    }
    Ok(())
}

fn encode_struct(
    name: &str,
    fields: &[(&'static str, Node)],
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    let schema = struct_schema(name).ok_or_else(|| {
        WireError::new(
            "unsupported_command_schema",
            format!("unregistered command struct {name}"),
        )
    })?;
    let mut encoded = Vec::with_capacity(fields.len());
    for (field_name, value) in fields {
        let rule = schema
            .fields
            .iter()
            .find(|rule| rule.name == *field_name)
            .ok_or_else(|| {
                WireError::new(
                    "unsupported_command_schema",
                    format!("unregistered command field {name}.{field_name}"),
                )
            })?;
        if encoded
            .iter()
            .any(|(id, _): &(u16, Vec<u8>)| *id == rule.id)
        {
            return Err(WireError::new(
                "duplicate_command_field",
                format!("duplicate command field {name}.{field_name}"),
            ));
        }
        let mut bytes = Vec::new();
        encode_node(value, rule.semantic, &mut bytes)?;
        encoded.push((rule.id, bytes));
    }
    for rule in schema.fields.iter().filter(|rule| rule.required) {
        if !encoded.iter().any(|(id, _)| *id == rule.id) {
            return Err(WireError::new(
                "missing_command_field",
                format!("missing command field {}.{}", schema.name, rule.name),
            ));
        }
    }
    encoded.sort_by_key(|(id, _)| *id);
    out.push(0x41);
    out.extend_from_slice(&schema.id.to_be_bytes());
    let count = u16::try_from(encoded.len())
        .map_err(|_| WireError::new("field_too_long", "too many command struct fields"))?;
    out.extend_from_slice(&count.to_be_bytes());
    for (id, bytes) in encoded {
        out.extend_from_slice(&id.to_be_bytes());
        put_u32(out, bytes.len())?;
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

fn encode_string(value: &str, semantic: Semantic, out: &mut Vec<u8>) -> Result<(), WireError> {
    match semantic {
        Semantic::Amount => {
            let amount = parse_u128(value)?;
            out.push(0x14);
            out.extend_from_slice(&amount.to_be_bytes());
        }
        Semantic::Hash32 => {
            out.push(0x21);
            out.extend_from_slice(&decode_fixed_hex::<32>(value, "hash")?);
        }
        Semantic::Key32 => {
            out.push(0x22);
            out.extend_from_slice(&decode_fixed_hex::<32>(value, "public key")?);
        }
        Semantic::Signature64 => {
            out.push(0x23);
            out.extend_from_slice(&decode_fixed_hex::<64>(value, "signature")?);
        }
        Semantic::Normal => {
            validate_text(value)?;
            out.push(0x20);
            put_u32(out, value.len())?;
            out.extend_from_slice(value.as_bytes());
        }
        Semantic::CanonicalSet => {
            return Err(WireError::new(
                "wrong_command_wire_type",
                "command set semantic applies only to a sequence",
            ));
        }
    }
    Ok(())
}
fn encode_framed(value: &Node, semantic: Semantic, out: &mut Vec<u8>) -> Result<(), WireError> {
    let mut encoded = Vec::new();
    encode_node(value, semantic, &mut encoded)?;
    put_u32(out, encoded.len())?;
    out.extend_from_slice(&encoded);
    Ok(())
}
fn parse_u128(value: &str) -> Result<u128, WireError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WireError::new(
            "noncanonical_number",
            "Amount is not canonical decimal",
        ));
    }
    value
        .parse()
        .map_err(|_| WireError::new("integer_overflow", "Amount exceeds u128"))
}
fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], WireError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WireError::new(
            "noncanonical_hex",
            format!("{label} must be lowercase {N}-byte hex"),
        ));
    }
    hex::decode(value)
        .map_err(|_| WireError::new("noncanonical_hex", label))?
        .try_into()
        .map_err(|_| WireError::new("noncanonical_hex", label))
}
fn validate_text(value: &str) -> Result<(), WireError> {
    if !value.nfc().eq(value.chars()) {
        return Err(WireError::new(
            "noncanonical_unicode",
            "command text must be NFC",
        ));
    }
    if value
        .chars()
        .any(|character| matches!(character as u32, 0x00..=0x1f | 0x7f..=0x9f))
    {
        return Err(WireError::new(
            "forbidden_control",
            "command text contains a control character",
        ));
    }
    Ok(())
}
fn put_u32(out: &mut Vec<u8>, value: usize) -> Result<(), WireError> {
    let value = u32::try_from(value)
        .map_err(|_| WireError::new("field_too_long", "command payload exceeds u32"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RLDCOIN_MAINNET_DOMAIN, RLDCOIN_TESTNET_DOMAIN};
    #[test]
    fn activation_has_the_only_empty_payload_and_distinct_network_hashes() {
        let command = ConsensusCommand::ActivatePendingValueRiskPolicy;
        assert!(command.wire_v1_command_payload_bytes().unwrap().is_empty());
        assert_ne!(
            command
                .wire_v1_command_hash(RLDCOIN_MAINNET_DOMAIN)
                .unwrap(),
            command
                .wire_v1_command_hash(RLDCOIN_TESTNET_DOMAIN)
                .unwrap()
        );
    }
    #[test]
    fn unknown_schema_items_fail_closed() {
        assert!(struct_schema("FutureConsensusCommand").is_none());
        assert!(enum_variant_tag("TransportClass", "FUTURE_TRANSPORT").is_none());
    }

    #[test]
    fn codec_only_unbond_v2_schema_ids_are_frozen_without_runtime_variants() {
        for (name, expected_id, expected_fields) in [
            ("RequestConsensusStakeUnbondV2", 0x1060, 19),
            ("CompleteConsensusStakeUnbondV2", 0x1061, 14),
            ("StakeStateResourceMutationEnvelopeV1", 0x1062, 9),
            ("StakePositionLiabilityHorizonV1", 0x1063, 10),
        ] {
            let schema = struct_schema(name).unwrap();
            assert_eq!(schema.id, expected_id);
            assert_eq!(schema.fields.len(), expected_fields);
            assert!(schema.fields.iter().all(|field| field.required));
        }
    }

    #[test]
    fn rust_matches_every_independent_command_accept_vector() {
        let bundle: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/wire-v1/commands.json"
        )))
        .unwrap();
        let cases = bundle["payload"]["cases"].as_array().unwrap();
        let mut accepted = 0usize;
        for case in cases {
            if case["expected"] != "accept" {
                continue;
            }
            accepted += 1;
            let command: ConsensusCommand =
                serde_json::from_value(case["command"].clone()).unwrap();
            let source = case["source"].as_object().unwrap();
            let domain = source["network_domain"].as_str().unwrap();
            assert_eq!(
                command.wire_v1_tag().to_string(),
                source["consensus_tag"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            let production_tag = match &command {
                ConsensusCommand::Production(command) => Some(command.wire_v1_tag().to_string()),
                _ => None,
            };
            assert_eq!(
                production_tag.as_deref(),
                source
                    .get("production_tag")
                    .and_then(serde_json::Value::as_str),
                "{}",
                case["name"]
            );
            assert_eq!(
                hex::encode(command.wire_v1_command_payload_bytes().unwrap()),
                source["payload"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert_eq!(
                hex::encode(command.wire_v1_command_bytes(domain).unwrap()),
                case["canonical_wire_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert_eq!(
                command.wire_v1_command_hash(domain).unwrap(),
                case["sha256"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
        assert_eq!(accepted, 54);
    }
}
