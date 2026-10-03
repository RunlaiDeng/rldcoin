# RLD-WIRE-V1 command commitments

Status: **normative command-body profile adopted by non-testnet consensus**.
Testnet and explicitly named historical records retain the legacy algorithms;
there is no V1-to-legacy verification fallback.

This document freezes the command body committed by `ConsensusProposal.command_hash`.
The words MUST, MUST NOT, REQUIRED, and MAY are normative.

## 1. Command envelope

The outer object is RLD-WIRE-V1 subject schema `0500 CommandCommitment`:

1. `network_domain:TEXT R` (64 bytes; exact supported network domain)
2. `consensus_tag:U16 R`
3. `production_tag:U16 O` (present exactly when `consensus_tag == 7`)
4. `payload:BYTES R` (at most 1,048,576 bytes)

`BYTES` has outer kind code `09`; its field payload is the raw bytes with no
inner length. The ordinary outer field length supplies the length.

Only consensus command tag 6 has an empty payload. Every other command has a
non-empty payload. Unknown tags, an inconsistent production tag, and an
oversized payload are invalid. The command hash is:

```text
SHA-256(ASCII("RLD-SUBJECT-HASH-PREIMAGE-V1") || 00 || schema-0500-wire)
```

JSON is only a vector/API projection. JSON serialization, Rust `Debug`, memory
layout, hash-map traversal order, and source declaration order are not command
commitment algorithms.

### R7.4 upgrade codec adoption boundary

Tags37 `SCHEDULE_UPGRADE` and38 `ACTIVATE_UPGRADE` are recognized by core
`ConsensusCommand` and certified candidate replay.
The exact [upgrade contract §13/§19](../../docs/spec/SAME-GENESIS-UPGRADE-CONTRACT.md)
bytes are unchanged: payload `RLDP || u16be(1) || 42 || u32be(object_length) ||
object`, using subject schemas1078/1079. Live node and isolated signer/witness
scheduling/activation guards remain closed. Main-WAL M0 admission supports
authenticated schedule and exact-build activation locks/commits through its
existing replay path; this internal support is not live role authorization.

## 2. Top-level tags

Consensus tags are fixed:

| Tag | Command | Payload |
| ---: | --- | --- |
| 1 | `LOCAL_PAYMENT` | `UniversalPaymentIntent` |
| 2 | `EXPORT_PAYMENT` | struct `2001` |
| 3 | `IMPORT_CAPSULE` | `TransitCapsule` |
| 4 | `FINALIZE_EXPORT` | `DestinationImportReceipt` |
| 5 | `SUBMIT_VALUE_RISK_POLICY_UPDATE` | `ValueRiskPolicyUpdate` |
| 6 | `ACTIVATE_PENDING_VALUE_RISK_POLICY` | empty |
| 7 | `PRODUCTION` | selected by `production_tag` |
| 8 | `SUBMIT_STAKE_AUTHORITY_UPDATE` | `StakeAuthorityGovernanceUpdateV1` |
| 9 | `DERIVE_NEXT_STAKE_EPOCH` | `DeriveNextStakeEpochRequestV1` |
| 10 | `LOCK_CONSENSUS_STAKE` | `LockConsensusStakeRequestV1` |
| 11 | `REGISTER_CONSENSUS_VALIDATOR` | `RegisterConsensusValidatorRequestV1` |
| 12 | `EXIT_CONSENSUS_VALIDATOR` | `ExitConsensusValidatorRequestV1` |
| 13 | `REQUEST_CONSENSUS_STAKE_UNBOND` | `RequestConsensusStakeUnbondV1` |
| 14 | `COMPLETE_CONSENSUS_STAKE_UNBOND` | `CompleteConsensusStakeUnbondV1` |
| 15 | `LOCK_CONSENSUS_STAKE_V2` | `LockConsensusStakeRequestV2` |
| 16 | `MIGRATE_CONSENSUS_STAKE_SLASH_TERMS` | `MigrateConsensusStakeSlashTermsV2` |
| 17 | `SLASH_CONSENSUS_STAKE` | `SlashConsensusStakeV1` |
| 18 | `PROPOSE_STAKE_STATE_RESOURCE_POLICY` | `ProposeStakeStateResourcePolicyV1` |
| 19 | `ACTIVATE_STAKE_STATE_RESOURCE_POLICY` | `ActivateStakeStateResourcePolicyV1` |
| 20 | `REGISTER_CONSENSUS_VALIDATOR_V2` | `RegisterConsensusValidatorRequestV2` |
| 21 | `LOCK_CONSENSUS_STAKE_V3` | `LockConsensusStakeRequestV3` |
| 22 | `MIGRATE_CONSENSUS_STAKE_RESOURCE` | `MigrateConsensusStakeResourceRequestV1` |
| 23 | `MIGRATE_CONSENSUS_CANDIDATE_RESOURCE` | `MigrateConsensusCandidateResourceRequestV1` |
| 24 | `DERIVE_NEXT_STAKE_EPOCH_V2` | `DeriveNextStakeEpochRequestV2` |
| 25 | `RENEW_STAKE_STATE_RESOURCE_BOND` | `RenewStakeStateResourceBondRequestV1` |

R6.17 adopts tags 18/19 for policy governance and R6.18 adopts tag 20 for
resource-bound candidate registration. R6.19 adopts tags 21/22 for a new
resource-bound position and exact migration of an active legacy position. R6.20
adopts tag 23 for one exact legacy candidate and tag 24 for exact derivation-v2
Epoch retention with funded candidate/position dependencies. R6.21A adopts tag
25 for a separately funded, append-only extension of one exact locked resource
bond history. None
accept caller-supplied usage: the ledger derives canonical
wire/persistent/signature/read/write units and atomically binds funding, fee,
state bond, optional change, pool accounting and nullifiers. Tag 25 cannot
rewrite the original bond, covered object, resource key/kind/owner or historical
charges; it binds the exact original record, current renewal-chain tip and a
strictly later lease. Tag 21 also binds
the separate stake principal, owner authorization and owner-signed objective
slash terms. Tag 22 binds an exact current authority and position commitment,
adds only the resource responsibility, and cannot alter principal, escrow or
authority membership. All require `VALUE_CAP_0`; unbond, slash-evidence and
settlement resource schemas remain non-routable.

R6.22B freezes the following **codec-only, non-routable** reservations. They
are not `ConsensusCommand` variants, remain invalid to the runtime command
envelope decoder, and cannot change ledger state:

| Reserved tag | Candidate command | Candidate payload |
| ---: | --- | --- |
| 26 | `REQUEST_CONSENSUS_STAKE_UNBOND_V2` | `RequestConsensusStakeUnbondV2` (`1060`) |
| 27 | `COMPLETE_CONSENSUS_STAKE_UNBOND_V2` | `CompleteConsensusStakeUnbondV2` (`1061`) |

The separate `ProductionCommand` tag 26 is a different namespace and does not
collide with these reservations. Runtime adoption requires a later protocol
change; these bytes alone do not unlock stake or authorize value.

Production tags are fixed in this order:

| Tag | Command | Payload |
| ---: | --- | --- |
| 1 | `ZONE_ADVERTISEMENT` | `ZoneAdvertisement` |
| 2 | `ROUTE_QUOTE_CREATE` | `CreateRouteQuoteRequest` |
| 3 | `ROUTE_QUOTE_REROUTE` | struct `2103` |
| 4 | `PAYMENT_REQUEST` | `PaymentRequest` |
| 5 | `RECIPIENT_RECEIPT` | `RecipientReceipt` |
| 6 | `GATEWAY_BOND` | `CreateGatewayBondRequest` |
| 7 | `REJECTION_CREATE` | struct `2107` |
| 8 | `REJECTION_CERTIFY` | struct `2108` |
| 9 | `RETURN_BEGIN` | `DestinationRejectionProof` |
| 10 | `RETURN_FINALIZE` | TEXT |
| 11 | `TRANSIT_CERTIFY` | struct `210b` |
| 12 | `TRAVELER_CREATE` | struct `210c` |
| 13 | `TRAVELER_IMPORT` | `TravelerCarryCapsule` |
| 14 | `DSC_ISSUE` | `SpendabilityCertificateRequest` |
| 15 | `LIQUIDITY_OFFER_CREATE` | `CreateLiquidityOfferRequest` |
| 16 | `LIQUIDITY_OFFER_TAKE` | `TakeLiquidityOfferRequest` |
| 17 | `PROTOCOL_SERVICE_ORDER` | `ProtocolServiceOrderRequest` |
| 18 | `SERVICE_ORDER` | struct `2112` |
| 19 | `SERVICE_LEASE` | struct `2113` |
| 20 | `SERVICE_COMPLETE` | struct `2114` |
| 21 | `ECONOMIC_CONTROL_ATTESTATION` | `EconomicControlAttestation` |
| 22 | `ECONOMIC_PRICE_ATTESTATION` | `EconomicPriceAttestation` |
| 23 | `ECONOMIC_RELEASE_POLICY` | `EconomicReleasePolicy` |
| 24 | `PROTOCOL_SERVICE_BOND_LOCK` | `ProtocolServiceBondLockRequest` |
| 25 | `PROTOCOL_SERVICE_BOND_SLASH` | `ProtocolServiceBondSlash` |
| 26 | `PROTOCOL_SERVICE_BOND_UNBOND` | struct `211a` |
| 27 | `PROTOCOL_RESERVE_RELEASE` | `ProtocolReserveReleaseRequest` |
| 28 | `VOYAGE_OPEN` | struct `211c` |
| 29 | `VOYAGE_SETTLE` | struct `211d` |
| 30 | `ERA_TRANSITION` | `EraContinuityCertificate` |

## 3. Payload grammar

A non-empty payload begins with ASCII `RLDP`, then big-endian `u16` version
`0001`, then exactly one value. All lengths and counts below are unsigned
big-endian. A decoder MUST consume the complete payload.

| Tag | Value encoding |
| ---: | --- |
| `01` / `02` | Boolean false / true |
| `10` | U8, one byte |
| `11` | U16, two bytes |
| `12` | U32, four bytes |
| `13` | U64, eight bytes |
| `14` | Amount/U128, sixteen bytes |
| `20` | TEXT: u32 byte length + canonical UTF-8 |
| `21` | HASH32: exactly 32 bytes |
| `22` | KEY32: exactly 32 bytes |
| `23` | SIGNATURE64: exactly 64 bytes |
| `30` | Unit |
| `31` | Option none |
| `32` | Option some: u32 encoded-value length + value |
| `40` | Sequence: u32 count, then each item as u32 length + value |
| `41` | Struct, described below |
| `42` | Bytes: u32 length + bytes |
| `50` | Unit enum: u16 enum id + u16 variant tag |

Signed integers and floating-point values are forbidden. Text MUST be valid
UTF-8 already in NFC and contain no C0/C1 controls. Amount is the canonical
unsigned `u128` value; its JSON projection is a shortest decimal string.

A struct is `41 || type_id:u16 || field_count:u16`, followed by fields in
strictly increasing numeric id order. Each field is `field_id:u16 ||
value_length:u32 || value`. Duplicate, reordered, missing-required, or unknown
fields are invalid. An optional field marked `O` is omitted only where the
table permits omission. An encoded Option is distinct from an omitted field.

Sequences preserve order unless a field is explicitly marked as a canonical
set. A canonical set sorts complete encoded items lexicographically and rejects
duplicates. V1 contains no command map type. A future command that serializes a
map, unregistered set, tuple, signed integer, float, unknown struct,
unknown field, or non-unit enum MUST fail closed until a later specification
assigns its canonical representation. Implementations MUST NOT use native map
iteration order.

## 4. Enum registry

Variant tags are one-based in the order shown:

| Enum id | Enum | Variants |
| ---: | --- | --- |
| `3001` | `ValueCap` | `VALUE_CAP_0`, `VALUE_CAP_1`, `VALUE_CAP_2`, `VALUE_CAP_3` |
| `3002` | `TransportClass` | `SUBLIGHT_DTN`, `CAUSAL_FTL`, `CAUSAL_WORMHOLE`, `CHRONOLOGY_UNSAFE` |
| `3003` | `CoinState` | `SPENDABLE`, `RESERVED`, `IN_TRANSIT`, `RETURNING`, `QUARANTINED`, `CONSUMED` |
| `3004` | `DestinationRejectionReason` | `RECIPIENT_DECLINED`, `POLICY_REJECTED`, `PROTOCOL_UNSUPPORTED`, `ROUTE_UNAVAILABLE`, `INVALID_COMMERCIAL_REQUEST` |
| `3005` | `ServiceRole` | `VALIDATOR`, `NOTARY`, `RELAY`, `STORAGE`, `ARCHIVE`, `GATEWAY`, `LIQUIDITY`, `CONTINUITY_CUSTODIAN`, `FTL_GATEWAY`, `OBSERVER` |
| `3006` | `ProtocolReservePoolKind` | `STARTUP_SERVICES`, `CONTINUITY_SERVICES`, `DEMAND_MATCHING` |
| `3007` | `EconomicControlRole` | `REQUESTER`, `SERVICE_PROVIDER`, `RELAY`, `LIQUIDITY_PROVIDER`, `VALIDATOR`, `NOTARY`, `PRICE_SOURCE` |
| `3008` | `StakePositionTypeV1` | `SELF_BOND`, `DELEGATION` |
| `3009` | `ConsensusStakeSlashEvidenceKindV1` | `DOUBLE_SIGN`, `CONFLICTING_CHECKPOINT`, `INVALID_STATE_COMMITMENT` |

Unknown enum ids and tags are invalid.

## 5. Struct registry

Notation is `id:name:type`; fields are in numeric-id order. `[]` is an ordered
sequence, `?` is an encoded Option, and `O` means the entire field may be
omitted. Every unmarked field is required.

| Type id | Struct | Fields |
| ---: | --- | --- |
| `1001` | `ZoneDescriptor` | `1 zone_id:TEXT; 2 display_name:TEXT; 3 genesis_root:HASH32; 4 identity_version:U16; 5 identity_hash_suite:TEXT; 6 network_domain:TEXT; 7 anchor_supply:AMOUNT; 8 genesis_validator_keys:KEY32[]; 9 genesis_notary_keys:KEY32[]; 10 currency_genesis_root:HASH32; 11 validator_keys:KEY32[]; 12 notary_keys:KEY32[]; 13 protocol_era:U64; 14 crypto_era:U64; 15 testnet:BOOL` |
| `1002` | `ValueRiskLimits` | `1 max_single_transfer:AMOUNT; 2 max_local_value_total:AMOUNT; 3 max_cross_zone_exposure:AMOUNT; 4 max_dsc_exposure:AMOUNT` |
| `1003` | `ValueRiskPolicyUpdate` | `1 update_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 policy_version:U16; 7 previous_policy_sequence:U64; 8 from_cap:ValueCap; 9 to_cap:ValueCap; 10 limits:ValueRiskLimits; 11 safety_case_hash:HASH32; 12 safety_case_valid_until_height:U64; 13 proposed_height:U64; 14 activate_after_height:U64; 15 expires_at_height:U64; 16 nonce:U64; 17 subject_hash:HASH32; 18 validator_qc:QuorumCertificate; 19 notary_qc:QuorumCertificate` |
| `1004` | `ZoneAdvertisement` | `1 descriptor:ZoneDescriptor; 2 sequence:U64; 3 endpoints:TEXT[]; 4 neighboring_zone_ids:TEXT[]; 5 transports:TransportClass[]; 6 subject_hash:HASH32; 7 validator_qc:QuorumCertificate` |
| `1005` | `PaymentRequest` | `1 request_id:TEXT; 2 recipient:TEXT; 3 recipient_public_key:KEY32; 4 destination_zone:TEXT; 5 currency_genesis_root:HASH32; 6 protocol_era:U64; 7 crypto_era:U64; 8 amount:AMOUNT; 9 memo:TEXT; 10 expires_at_height:U64; 11 nonce:U64; 12 signature:SIGNATURE64` |
| `1006` | `UniversalPaymentIntent` | `1 payment_id:TEXT; 2 source_zone:TEXT; 3 destination_zone:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 pricing_epoch:U64; 8 sender_public_key:KEY32; 9 recipient:TEXT; 10 coin_id:TEXT; 11 amount:AMOUNT; 12 max_fee:AMOUNT; 13 nonce:U64; 14 payment_request_id:TEXT? O; 15 payment_request:PaymentRequest? O; 16 route_quote_id:TEXT? O; 17 signature:SIGNATURE64` |
| `1007` | `SignedActionAuthorization` | `1 authorization_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 signer_public_key:KEY32; 7 action:TEXT; 8 payload_hash:HASH32; 9 nonce:U64; 10 signature:SIGNATURE64` |
| `1008` | `CreateRouteQuoteRequest` | `1 provider:TEXT; 2 destination_zone:TEXT; 3 route:TEXT[]; 4 transport:TransportClass; 5 base_fee:AMOUNT; 6 authorized_reroute_budget:AMOUNT; 7 expires_at_height:U64; 8 authorization:SignedActionAuthorization` |
| `1009` | `RerouteRouteQuoteRequest` | `1 failed_hop:TEXT; 2 replacement_route:TEXT[]; 3 incremental_fee:AMOUNT; 4 authorization:SignedActionAuthorization` |
| `100a` | `SignedAttestation` | `1 public_key:KEY32; 2 signature:SIGNATURE64` |
| `100b` | `QuorumCertificate` | `1 subject_hash:HASH32; 2 threshold:U16; 3 attestations:SET<SignedAttestation>; 4 testnet_simulated:BOOL` |
| `100c` | `CryptoSuiteDescriptor` | `1 suite_id:TEXT; 2 signature_algorithm:TEXT; 3 hash_algorithm:TEXT; 4 encoding:TEXT` |
| `100d` | `EraContinuityCertificate` | `1 zone_id:TEXT; 2 previous_protocol_era:U64; 3 new_protocol_era:U64; 4 previous_crypto_era:U64; 5 new_crypto_era:U64; 6 previous_certificate_hash:HASH32; 7 activation_checkpoint:HASH32; 8 irreversible_height:U64; 9 new_suite:CryptoSuiteDescriptor; 10 previous_validator_keys:KEY32[]; 11 previous_notary_keys:KEY32[]; 12 new_validator_keys:KEY32[]; 13 new_notary_keys:KEY32[]; 14 old_crypto_qc:QuorumCertificate; 15 new_crypto_qc:QuorumCertificate; 16 notary_qc:QuorumCertificate; 17 certificate_hash:HASH32` |
| `100e` | `OperationalProof` | `1 checkpoint_hash:HASH32; 2 object_hash:HASH32; 3 continuity_accumulator:HASH32; 4 lineage_merkle_path:HASH32[]; 5 transition_hashes:HASH32[]; 6 protocol_era:U64; 7 crypto_era:U64; 8 era_certificate_hash:HASH32; 9 supply_certificate_hash:HASH32; 10 transit_nullifier_commitment:HASH32` |
| `100f` | `CoinObject` | `1 object_id:TEXT; 2 lineage_root:HASH32; 3 parent_ids:TEXT[]; 4 owner:TEXT; 5 zone_id:TEXT; 6 amount:AMOUNT; 7 state:CoinState; 8 version:U64; 9 created_height:U64; 10 transit_id:TEXT?; 11 imported_from:TEXT?; 12 origin_zone:TEXT; 13 origin_genesis_root:HASH32` |
| `1010` | `SupplyBuckets` | `1 reserve:AMOUNT; 2 fee_pools:AMOUNT; 3 spendable:AMOUNT; 4 reserved:AMOUNT; 5 in_transit:AMOUNT; 6 returning:AMOUNT; 7 quarantined:AMOUNT; 8 imported_total:AMOUNT; 9 finalized_export_total:AMOUNT` |
| `1011` | `ProtocolReservePools` | `1 startup_services:AMOUNT; 2 continuity_services:AMOUNT; 3 demand_matching:AMOUNT` |
| `1012` | `SupplyConservationCertificate` | `1 zone_id:TEXT; 2 height:U64; 3 merkle_sum_root:HASH32; 4 buckets:SupplyBuckets; 5 reserve_pools:ProtocolReservePools; 6 conservation_position:AMOUNT; 7 anchor_supply:AMOUNT; 8 valid:BOOL` |
| `1013` | `GatewayEndorsement` | `1 bond_id:TEXT; 2 source_zone:TEXT; 3 gateway_public_key:KEY32; 4 capsule_subject_hash:HASH32; 5 signature:SIGNATURE64` |
| `1014` | `TransitCapsule` | `1 transit_id:TEXT; 2 payment_id:TEXT; 3 payment_request_id:TEXT? O; 4 payment_request:PaymentRequest? O; 5 route_quote_id:TEXT? O; 6 source_zone:TEXT; 7 destination_zone:TEXT; 8 source_descriptor:ZoneDescriptor; 9 recipient:TEXT; 10 amount:AMOUNT; 11 lineage_root:HASH32; 12 source_object_id:TEXT; 13 source_object_version:U64; 14 source_object:CoinObject; 15 source_supply:SupplyConservationCertificate; 16 origin_genesis_root:HASH32; 17 source_checkpoint:HASH32; 18 validator_qc:QuorumCertificate; 19 notary_qc:QuorumCertificate; 20 operational_proof:OperationalProof; 21 era_certificate:EraContinuityCertificate?; 22 gateway_endorsement:GatewayEndorsement? O; 23 transport:TransportClass` |
| `1015` | `CreateGatewayBondRequest` | `1 source_zone:TEXT; 2 owner:TEXT; 3 gateway_public_key:KEY32; 4 coin_id:TEXT; 5 amount:AMOUNT; 6 authorization:SignedActionAuthorization` |
| `1016` | `DestinationRejectionProof` | `1 rejection_id:TEXT; 2 transit_id:TEXT; 3 payment_id:TEXT; 4 source_zone:TEXT; 5 destination_zone:TEXT; 6 source_object_id:TEXT; 7 source_object_version:U64; 8 recipient:TEXT; 9 amount:AMOUNT; 10 reason:DestinationRejectionReason; 11 destination_descriptor:ZoneDescriptor; 12 destination_height:U64; 13 destination_checkpoint:HASH32; 14 validator_qc:QuorumCertificate; 15 notary_qc:QuorumCertificate` |
| `1017` | `DestinationImportReceipt` | `1 transit_id:TEXT; 2 payment_id:TEXT; 3 destination_zone:TEXT; 4 destination_coin_id:TEXT; 5 recipient:TEXT; 6 amount:AMOUNT; 7 destination_height:U64; 8 checkpoint_hash:HASH32` |
| `1018` | `RecipientReceipt` | `1 receipt_id:TEXT; 2 payment_id:TEXT; 3 settlement_reference:TEXT; 4 destination_zone:TEXT; 5 currency_genesis_root:HASH32; 6 protocol_era:U64; 7 crypto_era:U64; 8 recipient:TEXT; 9 recipient_public_key:KEY32; 10 amount:AMOUNT; 11 observed_destination_height:U64; 12 nonce:U64; 13 signature:SIGNATURE64` |
| `1019` | `SpendabilityCertificateRequest` | `1 payment_id:TEXT; 2 provider_coin_id:TEXT; 3 liquidity_provider:TEXT; 4 recipient:TEXT; 5 amount:AMOUNT; 6 settlement_claim_transit_id:TEXT; 7 authorization:SignedActionAuthorization` |
| `101a` | `CreateLiquidityOfferRequest` | `1 provider:TEXT; 2 coin_id:TEXT; 3 amount:AMOUNT; 4 minimum:AMOUNT; 5 maximum:AMOUNT; 6 expires_at_height:U64; 7 authorization:SignedActionAuthorization` |
| `101b` | `TakeLiquidityOfferRequest` | `1 offer_id:TEXT; 2 settlement_claim:TransitCapsule` |
| `101c` | `TravelerCarryCapsule` | `1 capsule_id:TEXT; 2 owner:TEXT; 3 issued_height:U64; 4 transit:TransitCapsule` |
| `101d` | `ProtocolServiceOrderRequest` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 reserve_pool:ProtocolReservePoolKind; 4 role:ServiceRole; 5 budget:AMOUNT; 6 description:TEXT; 7 matched_service_receipt_id:TEXT?; 8 protocol_era:U64; 9 crypto_era:U64; 10 nonce:U64; 11 subject_hash:HASH32; 12 validator_qc:QuorumCertificate; 13 notary_qc:QuorumCertificate` |
| `101e` | `EconomicControlMember` | `1 subject_id:TEXT; 2 control_group_id:TEXT; 3 role:EconomicControlRole; 4 validator_vote_bps:U32` |
| `101f` | `EconomicControlAttestation` | `1 attestation_id:TEXT; 2 zone_id:TEXT; 3 protocol_era:U64; 4 crypto_era:U64; 5 issued_height:U64; 6 valid_until_height:U64; 7 evidence_hash:HASH32; 8 auditor_public_key:KEY32; 9 auditor_control_group_id:TEXT; 10 members:EconomicControlMember[]; 11 auditor_signature:SIGNATURE64; 12 validator_qc:QuorumCertificate; 13 notary_qc:QuorumCertificate` |
| `1020` | `EconomicPriceAttestation` | `1 attestation_id:TEXT; 2 zone_id:TEXT; 3 work_id:TEXT; 4 control_attestation_id:TEXT; 5 source_public_key:KEY32; 6 source_control_group_id:TEXT; 7 amount:AMOUNT; 8 issued_height:U64; 9 valid_until_height:U64; 10 evidence_hash:HASH32; 11 signature:SIGNATURE64` |
| `1021` | `EconomicReleasePolicy` | `1 policy_id:TEXT; 2 zone_id:TEXT; 3 protocol_era:U64; 4 crypto_era:U64; 5 era_id:TEXT; 6 reserve_pool:ProtocolReservePoolKind; 7 era_release_cap:AMOUNT; 8 released:AMOUNT; 9 starts_at_height:U64; 10 ends_after_height:U64; 11 minimum_bond_coverage_bps:U32; 12 validator_qc:QuorumCertificate; 13 notary_qc:QuorumCertificate` |
| `1022` | `ProtocolServiceBondLockRequest` | `1 bond_id:TEXT; 2 order_id:TEXT; 3 lease_id:TEXT; 4 owner:TEXT; 5 coin_id:TEXT; 6 amount:AMOUNT; 7 challenge_end_height:U64; 8 unbond_after_height:U64; 9 slash_conditions_hash:HASH32; 10 authorization:SignedActionAuthorization` |
| `1023` | `ProtocolServiceBondSlash` | `1 slash_id:TEXT; 2 bond_id:TEXT; 3 amount:AMOUNT; 4 evidence_hash:HASH32; 5 validator_qc:QuorumCertificate; 6 notary_qc:QuorumCertificate` |
| `1024` | `ProtocolReserveReleaseRequest` | `1 release_id:TEXT; 2 order_id:TEXT; 3 lease_id:TEXT; 4 requester_subject_id:TEXT; 5 work_id:TEXT; 6 work_proof_hash:HASH32; 7 fee_receipt_ids:TEXT[]; 8 control_attestation_id:TEXT; 9 price_attestation_ids:TEXT[]; 10 bond_id:TEXT; 11 release_policy_id:TEXT; 12 reward:AMOUNT; 13 provider_authorization:SignedActionAuthorization; 14 completion_validator_qc:QuorumCertificate; 15 completion_notary_qc:QuorumCertificate` |
| `1025` | `StakeAuthorityPolicyCommandV1` | `1 policy_version:U16; 2 minimum_self_bond:AMOUNT; 3 minimum_delegation:AMOUNT; 4 candidate_maturity_blocks:U64; 5 stake_maturity_blocks:U64; 6 evidence_window_blocks:U64; 7 activation_delay_blocks:U64; 8 epoch_length_blocks:U64; 9 maximum_validators:U16` |
| `1026` | `StakeAuthorityCandidateCommandV1` | `1 validator_id:TEXT; 2 owner:TEXT; 3 public_key:KEY32; 4 key_era:U64; 5 registered_height:U64; 6 exit_height:U64?; 7 proof_of_possession:SIGNATURE64` |
| `1027` | `StakeAuthorityPositionCommandV1` | `1 position_id:TEXT; 2 position_type:StakePositionTypeV1; 3 validator_id:TEXT; 4 owner:TEXT; 5 source_coin_id:TEXT; 6 escrow_coin_id:TEXT; 7 amount:AMOUNT; 8 locked_height:U64; 9 committed_through_height:U64` |
| `1028` | `StakeUboControlRecordCommandV1` | `1 control_group:TEXT; 2 valid_from_height:U64; 3 challenge_ends_height:U64; 4 valid_through_height:U64; 5 evidence_hash:HASH32` |
| `1029` | `StakeUboControlEntryV1` | `1 validator_id:TEXT; 2 record:StakeUboControlRecordCommandV1` |
| `102a` | `StakeAuthorityGovernanceUpdateV1` | `1 update_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 authority_version:U16; 9 sequence:U64; 10 expected_previous_commitment:HASH32; 11 policy:StakeAuthorityPolicyCommandV1; 12 candidates:StakeAuthorityCandidateCommandV1[]; 13 positions:StakeAuthorityPositionCommandV1[]; 14 ubo_map_version:U16; 15 ubo_sequence:U64; 16 ubo_predecessor_commitment:HASH32; 17 ubo_verifier_set_commitment:HASH32; 18 ubo_evidence_root:HASH32; 19 ubo_validators:StakeUboControlEntryV1[]; 20 prospective_authority_commitment:HASH32; 21 subject_hash:HASH32; 22 validator_qc:QuorumCertificate; 23 notary_qc:QuorumCertificate` |
| `102b` | `DeriveNextStakeEpochRequestV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 expected_consensus_epoch:U64; 11 expected_snapshot_height:U64; 12 expected_snapshot_state_root:HASH32` |
| `102c` | `LockConsensusStakeRequestV1` | `1 position_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_type:StakePositionTypeV1; 11 validator_id:TEXT; 12 owner:TEXT; 13 source_coin_id:TEXT; 14 amount:AMOUNT; 15 committed_through_height:U64; 16 authorization:SignedActionAuthorization` |
| `102d` | `RegisterConsensusValidatorRequestV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 validator_id:TEXT; 11 owner:TEXT; 12 public_key:KEY32; 13 key_era:U64; 14 proof_of_possession:SIGNATURE64; 15 authorization:SignedActionAuthorization` |
| `102e` | `ExitConsensusValidatorRequestV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 validator_id:TEXT; 11 owner:TEXT; 12 public_key:KEY32; 13 key_era:U64; 14 registered_height:U64; 15 exit_height:U64; 16 proof_of_possession:SIGNATURE64; 17 authorization:SignedActionAuthorization` |
| `102f` | `RequestConsensusStakeUnbondV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_id:TEXT; 11 escrow_coin_id:TEXT; 12 owner:TEXT; 13 beneficiary:TEXT; 14 requested_withdraw_after_height:U64; 15 authorization:SignedActionAuthorization` |
| `1030` | `CompleteConsensusStakeUnbondV1` | `1 completion_id:TEXT; 2 request_id:TEXT; 3 zone_id:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 proposed_height:U64; 8 expires_at_height:U64; 9 expected_unbond_request_commitment:HASH32; 10 beneficiary:TEXT` |
| `1031` | `LockConsensusStakeRequestV2` | `1 position_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_type:StakePositionTypeV1; 11 validator_id:TEXT; 12 owner:TEXT; 13 source_coin_id:TEXT; 14 amount:AMOUNT; 15 committed_through_height:U64; 16 slash_terms_authorization:SignedActionAuthorization; 17 authorization:SignedActionAuthorization` |
| `1032` | `MigrateConsensusStakeSlashTermsV2` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_id:TEXT; 11 escrow_coin_id:TEXT; 12 owner:TEXT; 13 slash_terms_authorization:SignedActionAuthorization; 14 authorization:SignedActionAuthorization` |
| `1033` | `SignedConsensusVoteStatementV1` | `1 proposal_id:TEXT; 2 proposal_hash:HASH32; 3 zone_id:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 parent_height:U64; 8 parent_state_root:HASH32; 9 round:U64; 10 expected_state_root:HASH32; 11 voter_public_key:KEY32; 12 signature:SIGNATURE64` |
| `1034` | `SignedConsensusProposalStatementV1` | `1 proposal_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 parent_height:U64; 7 parent_state_root:HASH32; 8 round:U64; 9 proposer_public_key:KEY32; 10 command_hash:HASH32; 11 expected_height:U64; 12 expected_state_root:HASH32; 13 signature:SIGNATURE64` |
| `1035` | `SignedConsensusCheckpointStatementV1` | `1 network_domain:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 consensus_protocol_version:U64; 7 consensus_epoch:U64; 8 checkpoint_height:U128; 9 previous_checkpoint_hash:HASH32; 10 state_root:HASH32; 11 validator_id:TEXT; 12 validator_public_key:KEY32; 13 validator_key_era:U64; 14 signature:SIGNATURE64` |
| `1036` | `ConsensusStakeSlashEvidenceV1` | `1 kind:ConsensusStakeSlashEvidenceKindV1; 2 first_vote:SignedConsensusVoteStatementV1? O; 3 second_vote:SignedConsensusVoteStatementV1? O; 4 first_checkpoint:SignedConsensusCheckpointStatementV1? O; 5 second_checkpoint:SignedConsensusCheckpointStatementV1? O; 6 proposal:SignedConsensusProposalStatementV1? O; 7 invalid_vote:SignedConsensusVoteStatementV1? O` |
| `1037` | `SlashConsensusStakeV1` | `1 slash_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 consensus_epoch:U64; 11 derived_epoch_record_hash:HASH32; 12 position_id:TEXT; 13 escrow_coin_id:TEXT; 14 expected_position_amount:AMOUNT; 15 liability_commitment:HASH32; 16 expected_unbond_request_commitment:HASH32? O; 17 evidence_hash:HASH32; 18 evidence:ConsensusStakeSlashEvidenceV1` |
| `1038` | `StakeStateResourcePolicyV1` | `1 policy_version:U16; 2 sequence:U64; 3 previous_policy_commitment:HASH32; 4 activation_delay_blocks:U64; 5..9 base fees:AMOUNT; 10..13 unit fees:AMOUNT; 14 bond_per_persistent_byte:AMOUNT; 15..16 minimum bonds:AMOUNT; 17..20 lease/retention:U64; 21..27 record limits:U32; 28 maximum_total_stake_state_bytes:U64; 29..32 per-block limits:U32` |
| `1039` | `StakeStateResourceEnvelopeV1` | `1 resource_policy_sequence:U64; 2 resource_policy_commitment:HASH32; 3 sponsor:TEXT; 4 funding_coin_id:TEXT; 5 max_resource_fee:AMOUNT; 6 max_state_bond:AMOUNT; 7 lease_end_height:U64; 8 resource_subject_hash:HASH32; 9 authorization:SignedActionAuthorization` |
| `103c` | `ProposeStakeStateResourcePolicyV1` | `1 proposal_id:TEXT; 2 network_domain:TEXT; 3 zone_id:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 proposed_height:U64; 8 activate_after_height:U64; 9 expires_at_height:U64; 10 expected_current_policy_sequence:U64; 11 expected_current_policy_commitment:HASH32; 12 proposed_policy:StakeStateResourcePolicyV1; 13 proposed_policy_commitment:HASH32; 14 subject_hash:HASH32; 15 validator_qc:QuorumCertificate; 16 notary_qc:QuorumCertificate` |
| `103d` | `ActivateStakeStateResourcePolicyV1` | `1 activation_id:TEXT; 2 network_domain:TEXT; 3 zone_id:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 proposed_height:U64; 8 expires_at_height:U64; 9 proposal_id:TEXT; 10 expected_pending_policy_commitment:HASH32; 11 expected_current_policy_sequence:U64; 12 expected_current_policy_commitment:HASH32; 13 subject_hash:HASH32; 14 validator_qc:QuorumCertificate; 15 notary_qc:QuorumCertificate` |
| `1041` | `RegisterConsensusValidatorRequestV2` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 validator_id:TEXT; 11 owner:TEXT; 12 public_key:KEY32; 13 key_era:U64; 14 proof_of_possession:SIGNATURE64; 15 resource_envelope:StakeStateResourceEnvelopeV1; 16 authorization:SignedActionAuthorization` |
| `1042` | `LockConsensusStakeRequestV3` | `1 position_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_type:StakePositionTypeV1; 11 validator_id:TEXT; 12 owner:TEXT; 13 source_coin_id:TEXT; 14 amount:AMOUNT; 15 committed_through_height:U64; 16 slash_terms_authorization:SignedActionAuthorization; 17 resource_envelope:StakeStateResourceEnvelopeV1; 18 authorization:SignedActionAuthorization` |
| `1043` | `MigrateConsensusStakeResourceRequestV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_id:TEXT; 11 escrow_coin_id:TEXT; 12 owner:TEXT; 13 expected_position_commitment:HASH32; 14 resource_envelope:StakeStateResourceEnvelopeV1; 15 authorization:SignedActionAuthorization` |
| `1044` | `MigrateConsensusCandidateResourceRequestV1` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 validator_id:TEXT; 11 owner:TEXT; 12 public_key:KEY32; 13 key_era:U64; 14 registered_height:U64; 15 exit_height:U64? O; 16 proof_of_possession:SIGNATURE64; 17 expected_candidate_commitment:HASH32; 18 resource_envelope:StakeStateResourceEnvelopeV1; 19 authorization:SignedActionAuthorization` |
| `1045` | `DeriveNextStakeEpochRequestV2` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 expected_consensus_epoch:U64; 11 expected_snapshot_height:U64; 12 expected_snapshot_state_root:HASH32; 13 expected_derived_record_hash:HASH32; 14 payer:TEXT; 15 resource_envelope:StakeStateResourceEnvelopeV1; 16 authorization:SignedActionAuthorization` |
| `1046` | `RenewStakeStateResourceBondRequestV1` | `1 renewal_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 resource_key:TEXT; 9 resource_kind:StakeStateResourceKindV1; 10 resource_owner:TEXT; 11 expected_bond_id:HASH32; 12 expected_initial_bond_record_hash:HASH32; 13 expected_previous_renewal_hash:HASH32; 14 expected_current_lease_end_height:U64; 15 new_lease_end_height:U64; 16 resource_policy_sequence:U64; 17 resource_policy_commitment:HASH32; 18 sponsor:TEXT; 19 funding_coin_id:TEXT; 20 max_resource_fee:AMOUNT; 21 max_additional_bond:AMOUNT; 22 authorization:SignedActionAuthorization` |
| `1047` | `StakeStateBondRenewalRecordV1` | `1 renewal_id:TEXT; 2 resource_key:TEXT; 3 resource_kind:StakeStateResourceKindV1; 4 resource_owner:TEXT; 5 original_bond_id:HASH32; 6 initial_bond_record_hash:HASH32; 7 previous_renewal_hash:HASH32; 8 previous_lease_end_height:U64; 9 new_lease_end_height:U64; 10 resource_policy_sequence:U64; 11 resource_policy_commitment:HASH32; 12 sponsor:TEXT; 13 sponsor_authorization_id:TEXT; 14 funding_source_coin_id:TEXT; 15 bond_coin_id:TEXT; 16 additional_locked_amount:AMOUNT; 17 charged_renewal_fee:AMOUNT; 18 charged_wire_bytes:U32; 19 charged_persistent_bytes:U64; 20 charged_signature_checks:U32; 21 charged_state_reads:U32; 22 charged_state_writes:U32; 23 renewed_height:U64; 24 forfeit_after_height:U64; 25 record_hash:HASH32` |
| `1060` | `RequestConsensusStakeUnbondV2` | `1 request_id:TEXT; 2 zone_id:TEXT; 3 currency_genesis_root:HASH32; 4 protocol_era:U64; 5 crypto_era:U64; 6 proposed_height:U64; 7 expires_at_height:U64; 8 expected_authority_sequence:U64; 9 expected_authority_commitment:HASH32; 10 position_id:TEXT; 11 escrow_coin_id:TEXT; 12 owner:TEXT; 13 beneficiary:TEXT; 14 requested_withdraw_after_height:U64; 15 expected_position_commitment:HASH32; 16 expected_liability_horizon_commitment:HASH32; 17 expected_position_resource_bond_record_hash:HASH32; 18 resource_envelope:StakeStateResourceEnvelopeV1; 19 authorization:SignedActionAuthorization` |
| `1061` | `CompleteConsensusStakeUnbondV2` | `1 completion_id:TEXT; 2 request_id:TEXT; 3 zone_id:TEXT; 4 currency_genesis_root:HASH32; 5 protocol_era:U64; 6 crypto_era:U64; 7 proposed_height:U64; 8 expires_at_height:U64; 9 expected_unbond_request_commitment:HASH32; 10 beneficiary:TEXT; 11 expected_unbond_resource_bond_record_hash:HASH32; 12 expected_position_resource_bond_record_hash:HASH32; 13 expected_liability_horizon_commitment:HASH32; 14 resource_mutation_envelope:StakeStateResourceMutationEnvelopeV1` |
| `1062` | `StakeStateResourceMutationEnvelopeV1` | `1 resource_policy_sequence:U64; 2 resource_policy_commitment:HASH32; 3 sponsor:TEXT; 4 funding_coin_id:TEXT; 5 max_resource_fee:AMOUNT; 6 outer_operation_hash:HASH32; 7 expected_mutated_bond_record_hash:HASH32; 8 resource_subject_hash:HASH32; 9 authorization:SignedActionAuthorization` |
| `1063` | `StakePositionLiabilityHorizonV1` | `1 horizon_version:U16; 2 position_id:TEXT; 3 owner:TEXT; 4 escrow_coin_id:TEXT; 5 retained_liability_count:U64; 6 max_evidence_deadline_height:U128; 7 last_consensus_epoch:U64; 8 liability_accumulator_root:HASH32; 9 previous_horizon_commitment:HASH32; 10 horizon_commitment:HASH32` |

Command-only struct variants are:

| Type id | Struct | Fields |
| ---: | --- | --- |
| `2001` | `ConsensusCommand::ExportPayment` | `1 intent:UniversalPaymentIntent; 2 transport:TransportClass` |
| `2103` | `ProductionCommand::RouteQuoteReroute` | `1 quote_id:TEXT; 2 request:RerouteRouteQuoteRequest` |
| `2107` | `ProductionCommand::RejectionCreate` | `1 capsule:TransitCapsule; 2 reason:DestinationRejectionReason` |
| `2108` | `ProductionCommand::RejectionCertify` | `1 transit_id:TEXT; 2 validator_qc:QuorumCertificate; 3 notary_qc:QuorumCertificate` |
| `210b` | `ProductionCommand::TransitCertify` | `1 transit_id:TEXT; 2 validator_qc:QuorumCertificate; 3 notary_qc:QuorumCertificate` |
| `210c` | `ProductionCommand::TravelerCreate` | `1 intent:UniversalPaymentIntent; 2 transport:TransportClass` |
| `2112` | `ProductionCommand::ServiceOrder` | `1 buyer:TEXT; 2 coin_id:TEXT; 3 role:ServiceRole; 4 budget:AMOUNT; 5 description:TEXT; 6 authorization:SignedActionAuthorization` |
| `2113` | `ProductionCommand::ServiceLease` | `1 order_id:TEXT; 2 node_id:TEXT; 3 accepted_quote:AMOUNT; 4 authorization:SignedActionAuthorization` |
| `2114` | `ProductionCommand::ServiceComplete` | `1 lease_id:TEXT; 2 proof_hash:HASH32; 3 authorization:SignedActionAuthorization; 4 validator_qc:QuorumCertificate?; 5 notary_qc:QuorumCertificate?` |
| `211a` | `ProductionCommand::ProtocolServiceBondUnbond` | `1 bond_id:TEXT; 2 authorization:SignedActionAuthorization` |
| `211c` | `ProductionCommand::VoyageOpen` | `1 payer:TEXT; 2 coin_id:TEXT; 3 transit_id:TEXT; 4 budget:AMOUNT; 5 max_reward_per_hop:AMOUNT; 6 authorization:SignedActionAuthorization` |
| `211d` | `ProductionCommand::VoyageSettle` | `1 escrow_id:TEXT; 2 node_id:TEXT; 3 amount:AMOUNT; 4 downstream_receipt_hash:HASH32; 5 authorization:SignedActionAuthorization` |

## 6. Failure and evolution rules

All current command variants are covered above. A source change that adds a
command, nested struct field, enum variant, or new serialization shape does not
inherit V1 encoding. It MUST fail with an unsupported-schema error until this
registry, both implementations, and the content-addressed vectors are updated
together. Empty strings are never aliases for HASH32, KEY32, or SIGNATURE64.

For `StakeAuthorityGovernanceUpdateV1`, candidates MUST be strictly ordered by
validator ID, positions MUST be strictly ordered by position ID, and UBO
entries MUST be strictly ordered by validator ID; duplicate semantic IDs are
invalid even when the bytes are otherwise decodable. The command projection
uses `U64` heights because the current ledger/proposal height is `u64`, while
the derivation kernel models deep-time stake heights as `u128`. This profile
does not claim that the width boundary is suitable for a deep-time mainnet;
that migration is a separate release gate.

`LockConsensusStakeRequestV1` binds the exact staged authority predecessor,
owner, direct candidate, source Coin, position kind, amount, proposal/expiry
heights and commitment-through height into action
`LOCK_CONSENSUS_STAKE_V1`. A valid state transition consumes that unique
spendable source Coin, creates one stake-specific `Reserved` descendant plus
optional spendable change, records the escrow in the state root and appends
the exact position to a new authority sequence. The command cannot itself
change the runtime validator set, unlock, slash or withdraw stake.

`RegisterConsensusValidatorRequestV1` binds the exact authority predecessor,
owner, validator ID, strict consensus key/key era, proposal/expiry heights and
candidate-key proof into action `REGISTER_CONSENSUS_VALIDATOR_V1`. The ledger,
not the request, assigns `registered_height = proposed_height + 1`, and the
candidate must already have a separately governed UBO record. The broad
full-view command is bootstrap-only: after the first authority exists it
cannot change policy, candidates, positions or UBO state at all.

`RegisterConsensusValidatorRequestV2` preserves those candidate semantics while
adding a separately authorized sponsor envelope. The payload intentionally has no
usage field. Consensus derives the canonical command length, frozen logical
persistent footprint and fixed signature/read/write counters before verifying the
sponsor subject. The owner authorization commits to the exact envelope and sponsor
authorization. Admission atomically consumes the named funding Coin into fee,
`Reserved` bond and optional sponsor change. After resource-policy activation,
new V1 registration fails closed; already committed V1 history still replays.

`ExitConsensusValidatorRequestV1` binds the exact registered candidate plus a
future exit height into action `EXIT_CONSENSUS_VALIDATOR_V1`. The owner signs
the request and the consensus key signs a replacement candidate PoP containing
the exit height. Exit is one-way, cannot precede the policy notice window or
truncate an already-derived Epoch, and blocks new stake locks. Neither command
changes runtime validator membership.

`RequestConsensusStakeUnbondV1` binds the exact authority predecessor,
registered position and escrow, owner, owner-fixed beneficiary, proposal and
expiry height, and requested withdrawal height into action
`REQUEST_CONSENSUS_STAKE_UNBOND_V1`. A valid request removes the position from
the next staged authority but leaves its protected `Reserved` escrow in place.
The ledger rejects a withdrawal height earlier than the request notice delay,
the owner-signed `committed_through_height`, or any already-derived matching
validator obligation. The immutable request commitment is state-rooted and
cannot be shortened, cancelled or reintroduced by the broad bootstrap command.

`CompleteConsensusStakeUnbondV1` is permissionless only at maturity. It binds
the exact request commitment and immutable original-owner beneficiary. The
atomic transition consumes the protected escrow, removes it from the active
escrow registry, and creates exactly one equal `Spendable` child for that
beneficiary. Permanent unbond records preserve Lock/Request/Complete historical
replay and payout lineage. Neither unbond command changes runtime validator
membership, implements evidence slash, or relaxes `VALUE_CAP_0`.

`LockConsensusStakeRequestV2` keeps the V1 Coin/authority fields and adds a
separate owner authorization for the protocol-fixed objective-fault slash
terms. The `LOCK_CONSENSUS_STAKE_V2` authorization commits to the signed-terms
authorization, the two authorization IDs must differ, and both nullifiers are
consumed atomically. A derivation-policy-v2 authority rejects new V1 positions.

`LockConsensusStakeRequestV3` keeps the V2 stake and slash-liability semantics
and adds an independently authorized resource sponsor envelope. The stake
principal and resource-funding Coin must differ, all three authorization IDs
must be unique, and consensus derives 3 signature checks, 12 reads, 14 writes,
the canonical wire length and the frozen logical persistent footprint. The
resource lease must cover the position commitment plus terminal retention. One
staged transition consumes both sources, creates the protected stake escrow,
stake change when needed, resource fee, `Reserved` state bond and resource
change when needed, then roots the position, accounting, pool and nullifiers.
After resource-policy activation, new V1/V2 locks fail closed while already
committed history remains exactly replayable.

`MigrateConsensusStakeSlashTermsV2` attaches those exact retained terms to one
active legacy position after rechecking position ID, escrow, owner and current
authority predecessor. It changes no Coin or amount and rejects positions that
already have terms or an unbond record.

`MigrateConsensusStakeResourceRequestV1` is a separately funded, finite-inventory
migration for an exact active position that already has V2 slash terms. It binds
the current authority predecessor, position/escrow/owner and a commitment over
every position and slash-term field. Consensus derives 2 signature checks,
10 reads, 9 writes, canonical wire length and a footprint that retroactively
accounts the retained position copies plus its resource record. It consumes no
stake principal, creates no stake change and does not change authority state;
it only consumes the funding Coin into fee, `Reserved` bond and optional change.
Pending/completed unbonds, slashed positions and inexact retained state fail
closed.

`SlashConsensusStakeV1` is permissionless but not discretionary. It binds an
exact derived Epoch record, per-position liability, live escrow and optional
pending-unbond request commitment. The fixed-shape evidence union permits only:

- two canonically ordered, valid RLD-WIRE-V1 votes by the liability's historical
  key for the same consensus instance but different proposal/state commitment;
- two canonically ordered validator-signed checkpoints for the same exact
  checkpoint instance but different state roots; or
- a valid signed proposal plus that liability key's valid vote for the exact
  proposal hash and context but a different expected state root.

All evidence must fall inside the frozen activation/exit interval and be
submitted before the frozen evidence deadline. The current V1 transition
supports only the owner-accepted protocol-fixed 10,000-basis-point penalty:
the exact escrow is consumed, one equal `Reserved` descendant is assigned to
`RLD_CONSENSUS_SLASH_SAFETY_POOL_V2`, and an immutable slash record is
state-rooted. Replay protection is per frozen liability, not global per
validator fault:
`hash_parts("RLD-CONSENSUS-STAKE-SLASH-NULLIFIER-V1", evidence_hash, liability_commitment)`.
Consequently the same objective evidence can slash every independently frozen
self-bond/delegation liability for the faulty validator, while the same
liability cannot be slashed twice. There is no reporter reward and no
caller-selected amount or destination. An active position is removed from the
next staged authority; a pending unbond becomes `FULLY_SLASHED` with no payout.
A completed unbond cannot be slashed because completion cannot occur before
the liability deadline while slash submission must occur strictly before it.
This still does not activate the derived validator set or relax `VALUE_CAP_0`.

R6.14 retains the complete accepted `ConsensusStakeSlashEvidenceV1` in the
immutable slash record. The record is state-rooted and carried by serialized
ledger/checkpoint state and `AuditProofBundle`; restore/audit validation
re-runs the evidence verifier against the exact historical Epoch/liability and
requires the content hash, kind, fixed rate and fault/application height order
to match. This is a state/audit retention rule, not a new command tag or wire
schema, so the R6.14 command corpus remained 70 cases.

R6.17 adds two accepted governance commands, bringing the frozen command corpus
to 72 cases (48 accept / 24 reject), all 19 consensus variants and all 30
production variants. Proposal and activation histories are immutable and
exactly replayable. This adoption makes no resource-admission, fee, bond,
membership or real-value claim.

R6.18 adds candidate tag 20 plus an explicit rejection of caller-supplied
resource usage, bringing the corpus to 74 cases (49 accept / 25 reject).

R6.19 appends position tags 21/22 and a caller-supplied position-usage
rejection, bringing the corpus to 77 cases (51 accept / 26 reject), all 22
consensus variants and all 30 production variants. This adoption makes no
Epoch/unbond/slash-evidence/settlement, bond-settlement, dynamic-membership or
mainnet claim.

R6.20 appends legacy-candidate migration tag 23 and resource-bound Epoch tag 24,
plus one caller-supplied-usage rejection for each, bringing the corpus to 81
cases (53 accept / 28 reject), all 24 consensus variants and all 30 production
variants. This adoption makes no unbond/slash-evidence/renewal/settlement,
bond-settlement, dynamic-membership or mainnet claim.

R6.21A appends resource-bond renewal tag 25 plus its caller-supplied-usage
rejection, bringing the corpus to 83 cases (54 accept / 29 reject), all 25
consensus variants and all 30 production variants. The new command only extends
an exact locked candidate/position/Epoch resource history; unbond,
slash-evidence, settlement, bond-payout, dynamic-membership and mainnet-value
claims remain false.

The independent command bundle is
[`vectors/wire-v1/commands.json`](../../vectors/wire-v1/commands.json). It is
separate from, and does not rewrite, the original 31-vector bundle. It includes
an accept case for every consensus and production variant plus failures for
unknown/duplicate/reordered fields, unknown tags and enum tags, schema
substitution, UTF-8/NFC, numeric overflow, fixed-width hex, trailing data,
oversize, and byte tampering.
