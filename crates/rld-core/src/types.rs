use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    admission::{AdmissionCheckpointProofV1, AdmissionHash32, LedgerAdmissionStateV1},
    crypto::{hash_bytes, hash_parts},
    genesis::M0NetworkBirthStateV2,
    stake_epoch::{
        consensus_stake_slash_terms_payload_hash_v2, rebuild_stake_position_liability_horizons_v1,
        validate_ledger_derived_stake_epoch_v1, validate_ledger_stake_authority_state_v1,
        ConsensusStakePolicyV1, ConsensusStakePosition, ConsensusStakePositionKind,
        ConsensusStakeSlashPolicyV2, LedgerDerivedStakeEpochV1, LedgerStakeAuthorityStateV1,
        LedgerStakeAuthorityUpdateV1, StakePositionLiabilityHorizonV1, UboControlMap,
        UboControlRecord, ValidatorCandidateRecord,
    },
    stake_evidence::{
        verify_consensus_stake_slash_evidence_v1, ConsensusStakeSlashEvidenceKindV1,
        ConsensusStakeSlashEvidenceV1,
    },
    stake_resource_accounting::{
        stake_state_resource_policy_commitment_v1, validate_stake_state_resource_policy_v1,
        StakeStateResourceAccountingV1, ZERO_SHA256,
    },
    stake_resource_wire::{
        ActivateStakeStateResourcePolicyV1, ProposeStakeStateResourcePolicyV1,
        StakeStateBondStatusV1, StakeStateResourceEnvelopeV1, StakeStateResourceKindV1,
        StakeStateResourcePolicyV1,
    },
    verify_bytes,
    wire::{digest_hex, encode_source, preimage, WireError, WireSchema},
    Amount,
};

pub const MAX_OPERATIONAL_PROOF_BYTES: usize = 512 * 1024;
pub const MAX_RECENT_TRANSITIONS: usize = 64;
pub const MAX_LINEAGE_MERKLE_PATH: usize = 128;
pub const LEGACY_ZONE_IDENTITY_VERSION: u16 = 1;
pub const CURRENT_ZONE_IDENTITY_VERSION: u16 = 2;
pub const ZONE_IDENTITY_HASH_SUITE: &str = "SHA-256";
pub const RLDCOIN_MAINNET_DOMAIN: &str = "rldcoin:mainnet:v1";
pub const RLDCOIN_TESTNET_DOMAIN: &str = "rldcoin:testnet:v1";
pub const CURRENT_VALUE_RISK_POLICY_VERSION: u16 = 1;
pub const MIN_VALUE_CAP_UPGRADE_DELAY_BLOCKS: u64 = 100;

const fn legacy_zone_identity_version() -> u16 {
    LEGACY_ZONE_IDENTITY_VERSION
}

fn amount_is_zero(value: &Amount) -> bool {
    value.is_zero()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ZoneDescriptor {
    pub zone_id: String,
    pub display_name: String,
    pub genesis_root: String,
    #[serde(default = "legacy_zone_identity_version")]
    pub identity_version: u16,
    #[serde(default)]
    pub identity_hash_suite: String,
    #[serde(default)]
    pub network_domain: String,
    #[serde(default)]
    pub anchor_supply: Amount,
    #[serde(default)]
    pub genesis_validator_keys: Vec<String>,
    #[serde(default)]
    pub genesis_notary_keys: Vec<String>,
    #[serde(default)]
    pub currency_genesis_root: String,
    pub validator_keys: Vec<String>,
    pub notary_keys: Vec<String>,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub testnet: bool,
}

impl ZoneDescriptor {
    fn legacy_genesis_root_for(
        display_name: &str,
        anchor_supply: Amount,
        validator_keys: &[String],
        notary_keys: &[String],
    ) -> String {
        let validator_list = validator_keys.join("|");
        let notary_list = notary_keys.join("|");
        hash_parts(&[
            b"RLD-ZONE-GENESIS-V1",
            display_name.as_bytes(),
            &anchor_supply.0.to_be_bytes(),
            &(validator_keys.len() as u64).to_be_bytes(),
            validator_list.as_bytes(),
            &(notary_keys.len() as u64).to_be_bytes(),
            notary_list.as_bytes(),
        ])
    }

    pub fn genesis_root_for_v2(
        display_name: &str,
        anchor_supply: Amount,
        validator_keys: &[String],
        notary_keys: &[String],
        currency_genesis_root: &str,
        identity_hash_suite: &str,
        network_domain: &str,
    ) -> String {
        let validator_list = validator_keys.join("|");
        let notary_list = notary_keys.join("|");
        hash_parts(&[
            b"RLD-ZONE-GENESIS-V2",
            &CURRENT_ZONE_IDENTITY_VERSION.to_be_bytes(),
            identity_hash_suite.as_bytes(),
            network_domain.as_bytes(),
            currency_genesis_root.as_bytes(),
            display_name.as_bytes(),
            &anchor_supply.0.to_be_bytes(),
            &(validator_keys.len() as u64).to_be_bytes(),
            validator_list.as_bytes(),
            &(notary_keys.len() as u64).to_be_bytes(),
            notary_list.as_bytes(),
        ])
    }

    pub fn self_certifying_id(
        identity_version: u16,
        display_name: &str,
        genesis_root: &str,
    ) -> String {
        let digest = if identity_version == LEGACY_ZONE_IDENTITY_VERSION {
            hash_parts(&[display_name.as_bytes(), genesis_root.as_bytes()])
        } else {
            hash_parts(&[
                b"RLD-ZONE-ID-V2",
                &identity_version.to_be_bytes(),
                genesis_root.as_bytes(),
            ])
        };
        format!("zone-{}", &digest[..20])
    }

    pub fn validate_identity(&self) -> Result<(), String> {
        if self.display_name.trim().is_empty() || self.genesis_root.trim().is_empty() {
            return Err("Zone display name and genesis root are required".into());
        }
        let genesis_root = match self.identity_version {
            LEGACY_ZONE_IDENTITY_VERSION => {
                if !self.testnet {
                    return Err("legacy Zone identity is forbidden outside testnet".into());
                }
                Self::legacy_genesis_root_for(
                    &self.display_name,
                    self.anchor_supply,
                    &self.genesis_validator_keys,
                    &self.genesis_notary_keys,
                )
            }
            CURRENT_ZONE_IDENTITY_VERSION => {
                let expected_domain = if self.testnet {
                    RLDCOIN_TESTNET_DOMAIN
                } else {
                    RLDCOIN_MAINNET_DOMAIN
                };
                if self.identity_hash_suite != ZONE_IDENTITY_HASH_SUITE {
                    return Err("unsupported Zone identity hash suite".into());
                }
                if self.network_domain != expected_domain {
                    return Err("Zone identity network domain mismatch".into());
                }
                if self.currency_genesis_root.trim().is_empty() {
                    return Err("Zone identity currency genesis root is required".into());
                }
                Self::genesis_root_for_v2(
                    &self.display_name,
                    self.anchor_supply,
                    &self.genesis_validator_keys,
                    &self.genesis_notary_keys,
                    &self.currency_genesis_root,
                    &self.identity_hash_suite,
                    &self.network_domain,
                )
            }
            version => return Err(format!("unsupported Zone identity version {version}")),
        };
        if self.genesis_root != genesis_root {
            return Err("Zone genesis descriptor commitment is invalid".into());
        }
        let expected = Self::self_certifying_id(
            self.identity_version,
            &self.display_name,
            &self.genesis_root,
        );
        if self.zone_id != expected {
            return Err("Zone id does not match its self-certifying descriptor".into());
        }
        Ok(())
    }
}

/// A consensus-visible ceiling on how much real value a Zone may expose.
///
/// Testnet keeps its historical unrestricted semantics. Every non-test Zone
/// starts at `VALUE_CAP_0` and therefore rejects value-bearing transitions
/// until an explicitly signed, delayed policy update is activated.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueCap {
    #[default]
    #[serde(rename = "VALUE_CAP_0", alias = "VALUE_CAP0")]
    ValueCap0,
    #[serde(rename = "VALUE_CAP_1", alias = "VALUE_CAP1")]
    ValueCap1,
    #[serde(rename = "VALUE_CAP_2", alias = "VALUE_CAP2")]
    ValueCap2,
    #[serde(rename = "VALUE_CAP_3", alias = "VALUE_CAP3")]
    ValueCap3,
}

impl ValueCap {
    pub const fn code(self) -> u8 {
        match self {
            Self::ValueCap0 => 0,
            Self::ValueCap1 => 1,
            Self::ValueCap2 => 2,
            Self::ValueCap3 => 3,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueRiskLimits {
    pub max_single_transfer: Amount,
    pub max_local_value_total: Amount,
    pub max_cross_zone_exposure: Amount,
    pub max_dsc_exposure: Amount,
}

impl ValueRiskLimits {
    pub fn validate_for_cap(&self, cap: ValueCap) -> Result<(), String> {
        let all_zero = self.max_single_transfer.is_zero()
            && self.max_local_value_total.is_zero()
            && self.max_cross_zone_exposure.is_zero()
            && self.max_dsc_exposure.is_zero();
        if cap == ValueCap::ValueCap0 {
            return all_zero
                .then_some(())
                .ok_or_else(|| "VALUE_CAP_0 requires all real-value limits to be zero".into());
        }
        if self.max_single_transfer.is_zero() {
            return Err("enabled value caps require a non-zero single-transfer limit".into());
        }
        let path_limits = [
            self.max_local_value_total,
            self.max_cross_zone_exposure,
            self.max_dsc_exposure,
        ];
        if path_limits.iter().all(|limit| limit.is_zero()) {
            return Err("enabled value caps require at least one enabled value path".into());
        }
        if path_limits
            .iter()
            .any(|limit| !limit.is_zero() && self.max_single_transfer > *limit)
        {
            return Err("single-transfer limit cannot exceed an enabled path total".into());
        }
        Ok(())
    }

    pub fn increases_any_limit_over(&self, previous: &Self) -> bool {
        self.max_single_transfer > previous.max_single_transfer
            || self.max_local_value_total > previous.max_local_value_total
            || self.max_cross_zone_exposure > previous.max_cross_zone_exposure
            || self.max_dsc_exposure > previous.max_dsc_exposure
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueRiskExposure {
    /// Conservative lifetime total accepted by same-Zone payments.
    pub local_value_total: Amount,
    /// Outstanding source exports plus destination-imported foreign value.
    pub cross_zone_exposure: Amount,
    /// Destination liquidity advanced before the matching import settles.
    pub dsc_exposure: Amount,
    /// Non-test commitments that prepaid local-value exposure before closeout.
    #[serde(default)]
    pub local_commitment_amounts: BTreeMap<String, Amount>,
    /// Non-test liquidity offers that prepaid DSC exposure before closeout.
    #[serde(default)]
    pub dsc_commitment_amounts: BTreeMap<String, Amount>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueRiskPolicyUpdate {
    pub update_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub policy_version: u16,
    pub previous_policy_sequence: u64,
    pub from_cap: ValueCap,
    pub to_cap: ValueCap,
    pub limits: ValueRiskLimits,
    /// Commitment to the reviewed rollout evidence and safety case.
    pub safety_case_hash: String,
    /// Last height before which the referenced safety evidence remains valid.
    #[serde(default)]
    pub safety_case_valid_until_height: u64,
    pub proposed_height: u64,
    pub activate_after_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl ValueRiskPolicyUpdate {
    pub fn compute_subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-VALUE-RISK-POLICY-UPDATE-V1",
            self.update_id.as_bytes(),
            self.zone_id.as_bytes(),
            self.currency_genesis_root.as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
            &self.policy_version.to_be_bytes(),
            &self.previous_policy_sequence.to_be_bytes(),
            &[self.from_cap.code()],
            &[self.to_cap.code()],
            &self.limits.max_single_transfer.0.to_be_bytes(),
            &self.limits.max_local_value_total.0.to_be_bytes(),
            &self.limits.max_cross_zone_exposure.0.to_be_bytes(),
            &self.limits.max_dsc_exposure.0.to_be_bytes(),
            self.safety_case_hash.as_bytes(),
            &self.safety_case_valid_until_height.to_be_bytes(),
            &self.proposed_height.to_be_bytes(),
            &self.activate_after_height.to_be_bytes(),
            &self.expires_at_height.to_be_bytes(),
            &self.nonce.to_be_bytes(),
        ])
    }

    /// Candidate mainnet RLD-WIRE-V1 subject bytes.
    ///
    /// This is deliberately separate from `compute_subject_hash`, which is the
    /// legacy/testnet and historical-record algorithm.
    pub fn wire_v1_subject_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        encode_wire_json(
            WireSchema::ValueRiskPolicyUpdate,
            serde_json::json!({
                "network_domain": network_domain,
                "update_id": self.update_id,
                "zone_id": self.zone_id,
                "currency_genesis_root": self.currency_genesis_root,
                "protocol_era": self.protocol_era.to_string(),
                "crypto_era": self.crypto_era.to_string(),
                "policy_version": self.policy_version.to_string(),
                "previous_policy_sequence": self.previous_policy_sequence.to_string(),
                "from_cap": self.from_cap.code().to_string(),
                "to_cap": self.to_cap.code().to_string(),
                "max_single_transfer": self.limits.max_single_transfer.0.to_string(),
                "max_local_value_total": self.limits.max_local_value_total.0.to_string(),
                "max_cross_zone_exposure": self.limits.max_cross_zone_exposure.0.to_string(),
                "max_dsc_exposure": self.limits.max_dsc_exposure.0.to_string(),
                "safety_case_hash": self.safety_case_hash,
                "safety_case_valid_until_height": u128::from(self.safety_case_valid_until_height).to_string(),
                "proposed_height": u128::from(self.proposed_height).to_string(),
                "activate_after_height": u128::from(self.activate_after_height).to_string(),
                "expires_at_height": u128::from(self.expires_at_height).to_string(),
                "nonce": self.nonce.to_string(),
            }),
        )
    }

    pub fn wire_v1_subject_hash(&self, network_domain: &str) -> Result<String, WireError> {
        let wire = self.wire_v1_subject_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::ValueRiskPolicyUpdate, &wire))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValueRiskPolicy {
    pub version: u16,
    pub policy_sequence: u64,
    pub current_cap: ValueCap,
    /// Never resets, so a downshift cannot disguise prior real-value activation.
    pub ever_enabled: bool,
    pub limits: ValueRiskLimits,
    pub exposure: ValueRiskExposure,
    pub safety_case_hash: String,
    #[serde(default)]
    pub safety_case_valid_until_height: u64,
    pub activated_height: u64,
    pub pending_update: Option<ValueRiskPolicyUpdate>,
}

impl Default for ValueRiskPolicy {
    fn default() -> Self {
        Self {
            version: CURRENT_VALUE_RISK_POLICY_VERSION,
            policy_sequence: 0,
            current_cap: ValueCap::ValueCap0,
            ever_enabled: false,
            limits: ValueRiskLimits::default(),
            exposure: ValueRiskExposure::default(),
            safety_case_hash: String::new(),
            safety_case_valid_until_height: 0,
            activated_height: 0,
            pending_update: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ZoneTrustPolicy {
    LightClient,
    DualQc,
    BondedGateway,
    ObserveOnly,
    Quarantined,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportClass {
    SublightDtn,
    CausalFtl,
    CausalWormhole,
    ChronologyUnsafe,
}

impl TransportClass {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::SublightDtn => "SUBLIGHT_DTN",
            Self::CausalFtl => "CAUSAL_FTL",
            Self::CausalWormhole => "CAUSAL_WORMHOLE",
            Self::ChronologyUnsafe => "CHRONOLOGY_UNSAFE",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneAdvertisement {
    pub descriptor: ZoneDescriptor,
    pub sequence: u64,
    pub endpoints: Vec<String>,
    pub neighboring_zone_ids: Vec<String>,
    pub transports: Vec<TransportClass>,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
}

impl ZoneAdvertisement {
    pub fn compute_subject_hash(&self) -> String {
        let endpoints = self.endpoints.join("|");
        let neighbors = self.neighboring_zone_ids.join("|");
        let transports = self
            .transports
            .iter()
            .map(TransportClass::wire_name)
            .collect::<Vec<_>>()
            .join("|");
        hash_parts(&[
            b"RLD-ZONE-ADVERTISEMENT-V1",
            self.descriptor.zone_id.as_bytes(),
            self.descriptor.genesis_root.as_bytes(),
            &self.descriptor.protocol_era.to_be_bytes(),
            &self.descriptor.crypto_era.to_be_bytes(),
            &self.sequence.to_be_bytes(),
            endpoints.as_bytes(),
            neighbors.as_bytes(),
            transports.as_bytes(),
        ])
    }

    pub fn verify(&self) -> Result<(), String> {
        self.descriptor.validate_identity()?;
        if self.descriptor.protocol_era != 1
            || self.descriptor.crypto_era != 1
            || self.descriptor.validator_keys != self.descriptor.genesis_validator_keys
            || self.descriptor.notary_keys != self.descriptor.genesis_notary_keys
        {
            return Err(
                "era-migrated Zone discovery requires a continuity proof and is not accepted by this discovery version"
                    .into(),
            );
        }
        if self.sequence == 0 || self.endpoints.is_empty() || self.endpoints.len() > 16 {
            return Err("Zone advertisement requires a sequence and 1-16 endpoints".into());
        }
        if self.neighboring_zone_ids.len() > 128 || self.transports.len() > 8 {
            return Err("Zone advertisement exceeds discovery bounds".into());
        }
        if !strictly_sorted_unique(&self.endpoints)
            || !strictly_sorted_unique(&self.neighboring_zone_ids)
        {
            return Err(
                "Zone advertisement endpoints and neighbors must be sorted and unique".into(),
            );
        }
        if self.endpoints.iter().any(|endpoint| {
            endpoint.len() > 2048
                || !(endpoint.starts_with("https://")
                    || (self.descriptor.testnet && endpoint.starts_with("http://")))
        }) {
            return Err("Zone advertisement contains an invalid endpoint".into());
        }
        let subject = self.compute_subject_hash();
        if self.subject_hash != subject || self.validator_qc.subject_hash != subject {
            return Err("Zone advertisement subject binding mismatch".into());
        }
        if self.validator_qc.testnet_simulated {
            if self.descriptor.testnet && self.descriptor.validator_keys.is_empty() {
                return Ok(());
            }
            return Err("simulated discovery quorum is forbidden for a configured Zone".into());
        }
        self.validator_qc.verify(&self.descriptor.validator_keys)
    }
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoinState {
    Spendable,
    Reserved,
    InTransit,
    Returning,
    Quarantined,
    Consumed,
}

impl CoinState {
    pub fn carries_supply(&self) -> bool {
        !matches!(self, Self::Consumed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoinObject {
    pub object_id: String,
    pub lineage_root: String,
    pub parent_ids: Vec<String>,
    pub owner: String,
    pub zone_id: String,
    pub amount: Amount,
    pub state: CoinState,
    pub version: u64,
    pub created_height: u64,
    pub transit_id: Option<String>,
    pub imported_from: Option<String>,
    #[serde(default)]
    pub origin_zone: String,
    #[serde(default)]
    pub origin_genesis_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRequest {
    pub request_id: String,
    pub recipient: String,
    pub recipient_public_key: String,
    pub destination_zone: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    pub amount: Amount,
    pub memo: String,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub signature: String,
}

impl PaymentRequest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-PAYMENT-REQUEST-V2".to_vec();
        put_string(&mut bytes, &self.request_id);
        put_string(&mut bytes, &self.recipient);
        put_string(&mut bytes, &self.recipient_public_key);
        put_string(&mut bytes, &self.destination_zone);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.amount.0.to_be_bytes());
        put_string(&mut bytes, &self.memo);
        bytes.extend_from_slice(&self.expires_at_height.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.request_id.trim().is_empty() || self.amount.is_zero() {
            return Err("payment request id and non-zero amount are required".into());
        }
        if self.memo.len() > 512 {
            return Err("payment request memo exceeds 512 bytes".into());
        }
        let expected_recipient = format!(
            "rld:{}:{}",
            self.destination_zone, self.recipient_public_key
        );
        if self.recipient != expected_recipient {
            return Err("payment request recipient does not match its signer".into());
        }
        verify_bytes(
            &self.recipient_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }

    pub fn commitment_hash(&self) -> String {
        hash_parts(&[&self.signing_bytes(), self.signature.as_bytes()])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UniversalPaymentIntent {
    pub payment_id: String,
    pub source_zone: String,
    pub destination_zone: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    #[serde(default)]
    pub pricing_epoch: u64,
    pub sender_public_key: String,
    pub recipient: String,
    pub coin_id: String,
    pub amount: Amount,
    pub max_fee: Amount,
    pub nonce: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request: Option<PaymentRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_quote_id: Option<String>,
    pub signature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceVector {
    pub ingress_bytes: u64,
    pub signature_checks_classic: u64,
    pub signature_checks_pq: u64,
    pub state_reads: u64,
    pub state_writes: u64,
    pub new_state_bytes: u64,
    pub proof_bytes: u64,
    pub proof_verification_units: u64,
    pub consensus_units: u64,
    pub archive_byte_epochs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePriceSchedule {
    pub pricing_epoch: u64,
    pub ingress_byte_price: Amount,
    pub signature_check_classic_price: Amount,
    pub signature_check_pq_price: Amount,
    pub state_read_price: Amount,
    pub state_write_price: Amount,
    pub new_state_byte_price: Amount,
    pub proof_byte_price: Amount,
    pub proof_verification_unit_price: Amount,
    pub consensus_unit_price: Amount,
    pub archive_byte_epoch_price: Amount,
}

impl ResourcePriceSchedule {
    pub fn quote(&self, resources: &ResourceVector) -> Result<Amount, String> {
        let priced = [
            (resources.ingress_bytes, self.ingress_byte_price),
            (
                resources.signature_checks_classic,
                self.signature_check_classic_price,
            ),
            (resources.signature_checks_pq, self.signature_check_pq_price),
            (resources.state_reads, self.state_read_price),
            (resources.state_writes, self.state_write_price),
            (resources.new_state_bytes, self.new_state_byte_price),
            (resources.proof_bytes, self.proof_byte_price),
            (
                resources.proof_verification_units,
                self.proof_verification_unit_price,
            ),
            (resources.consensus_units, self.consensus_unit_price),
            (resources.archive_byte_epochs, self.archive_byte_epoch_price),
        ];
        priced
            .into_iter()
            .try_fold(Amount::ZERO, |total, (units, unit_price)| {
                let component = u128::from(units)
                    .checked_mul(unit_price.0)
                    .map(Amount)
                    .ok_or_else(|| "resource fee multiplication overflow".to_string())?;
                total
                    .checked_add(component)
                    .map_err(|error| error.to_string())
            })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochFeePool {
    pub pricing_epoch: u64,
    pub collected: Amount,
    pub charged_payments: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionCommand {
    ZoneAdvertisement(ZoneAdvertisement),
    RouteQuoteCreate(CreateRouteQuoteRequest),
    RouteQuoteReroute {
        quote_id: String,
        request: RerouteRouteQuoteRequest,
    },
    PaymentRequest(PaymentRequest),
    RecipientReceipt(RecipientReceipt),
    GatewayBond(CreateGatewayBondRequest),
    RejectionCreate {
        capsule: Box<TransitCapsule>,
        reason: DestinationRejectionReason,
    },
    RejectionCertify {
        transit_id: String,
        validator_qc: QuorumCertificate,
        notary_qc: QuorumCertificate,
    },
    ReturnBegin(DestinationRejectionProof),
    ReturnFinalize(String),
    TransitCertify {
        transit_id: String,
        validator_qc: QuorumCertificate,
        notary_qc: QuorumCertificate,
    },
    TravelerCreate {
        intent: UniversalPaymentIntent,
        transport: TransportClass,
    },
    TravelerImport(Box<TravelerCarryCapsule>),
    DscIssue(SpendabilityCertificateRequest),
    LiquidityOfferCreate(CreateLiquidityOfferRequest),
    LiquidityOfferTake(Box<TakeLiquidityOfferRequest>),
    ProtocolServiceOrder(ProtocolServiceOrderRequest),
    ServiceOrder {
        buyer: String,
        coin_id: String,
        role: ServiceRole,
        budget: Amount,
        description: String,
        authorization: SignedActionAuthorization,
    },
    ServiceLease {
        order_id: String,
        node_id: String,
        accepted_quote: Amount,
        authorization: SignedActionAuthorization,
    },
    ServiceComplete {
        lease_id: String,
        proof_hash: String,
        authorization: SignedActionAuthorization,
        validator_qc: Option<QuorumCertificate>,
        notary_qc: Option<QuorumCertificate>,
    },
    EconomicControlAttestation(EconomicControlAttestation),
    EconomicPriceAttestation(EconomicPriceAttestation),
    EconomicReleasePolicy(EconomicReleasePolicy),
    ProtocolServiceBondLock(ProtocolServiceBondLockRequest),
    ProtocolServiceBondSlash(ProtocolServiceBondSlash),
    ProtocolServiceBondUnbond {
        bond_id: String,
        authorization: SignedActionAuthorization,
    },
    ProtocolReserveRelease(Box<ProtocolReserveReleaseRequest>),
    VoyageOpen {
        payer: String,
        coin_id: String,
        transit_id: String,
        budget: Amount,
        max_reward_per_hop: Amount,
        authorization: SignedActionAuthorization,
    },
    VoyageSettle {
        escrow_id: String,
        node_id: String,
        amount: Amount,
        downstream_receipt_hash: String,
        authorization: SignedActionAuthorization,
    },
    EraTransition(Box<EraContinuityCertificate>),
}

impl ProductionCommand {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::ZoneAdvertisement(_) => "ZONE_ADVERTISEMENT",
            Self::RouteQuoteCreate(_) => "ROUTE_QUOTE_CREATE",
            Self::RouteQuoteReroute { .. } => "ROUTE_QUOTE_REROUTE",
            Self::PaymentRequest(_) => "PAYMENT_REQUEST",
            Self::RecipientReceipt(_) => "RECIPIENT_RECEIPT",
            Self::GatewayBond(_) => "GATEWAY_BOND",
            Self::RejectionCreate { .. } => "REJECTION_CREATE",
            Self::RejectionCertify { .. } => "REJECTION_CERTIFY",
            Self::ReturnBegin(_) => "RETURN_BEGIN",
            Self::ReturnFinalize(_) => "RETURN_FINALIZE",
            Self::TransitCertify { .. } => "TRANSIT_CERTIFY",
            Self::TravelerCreate { .. } => "TRAVELER_CREATE",
            Self::TravelerImport(_) => "TRAVELER_IMPORT",
            Self::DscIssue(_) => "DSC_ISSUE",
            Self::LiquidityOfferCreate(_) => "LIQUIDITY_OFFER_CREATE",
            Self::LiquidityOfferTake(_) => "LIQUIDITY_OFFER_TAKE",
            Self::ProtocolServiceOrder(_) => "PROTOCOL_SERVICE_ORDER",
            Self::ServiceOrder { .. } => "SERVICE_ORDER",
            Self::ServiceLease { .. } => "SERVICE_LEASE",
            Self::ServiceComplete { .. } => "SERVICE_COMPLETE",
            Self::EconomicControlAttestation(_) => "ECONOMIC_CONTROL_ATTESTATION",
            Self::EconomicPriceAttestation(_) => "ECONOMIC_PRICE_ATTESTATION",
            Self::EconomicReleasePolicy(_) => "ECONOMIC_RELEASE_POLICY",
            Self::ProtocolServiceBondLock(_) => "PROTOCOL_SERVICE_BOND_LOCK",
            Self::ProtocolServiceBondSlash(_) => "PROTOCOL_SERVICE_BOND_SLASH",
            Self::ProtocolServiceBondUnbond { .. } => "PROTOCOL_SERVICE_BOND_UNBOND",
            Self::ProtocolReserveRelease(_) => "PROTOCOL_RESERVE_RELEASE",
            Self::VoyageOpen { .. } => "VOYAGE_OPEN",
            Self::VoyageSettle { .. } => "VOYAGE_SETTLE",
            Self::EraTransition(_) => "ERA_TRANSITION",
        }
    }
}

/// Wire-safe position kind used by the consensus command that stages stake
/// authority.  The ledger converts this unit enum into the richer internal
/// position kind only after the command has passed canonical ordering checks.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakePositionTypeV1 {
    SelfBond,
    Delegation,
}

impl StakePositionTypeV1 {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SelfBond => "SELF_BOND",
            Self::Delegation => "DELEGATION",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeAuthorityPolicyCommandV1 {
    pub policy_version: u16,
    pub minimum_self_bond: Amount,
    pub minimum_delegation: Amount,
    pub candidate_maturity_blocks: u64,
    pub stake_maturity_blocks: u64,
    pub evidence_window_blocks: u64,
    pub activation_delay_blocks: u64,
    pub epoch_length_blocks: u64,
    pub maximum_validators: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeAuthorityCandidateCommandV1 {
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub registered_height: u64,
    pub exit_height: Option<u64>,
    pub proof_of_possession: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeAuthorityPositionCommandV1 {
    pub position_id: String,
    pub position_type: StakePositionTypeV1,
    pub validator_id: String,
    pub owner: String,
    pub source_coin_id: String,
    pub escrow_coin_id: String,
    pub amount: Amount,
    pub locked_height: u64,
    pub committed_through_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeUboControlRecordCommandV1 {
    pub control_group: String,
    pub valid_from_height: u64,
    pub challenge_ends_height: u64,
    pub valid_through_height: u64,
    pub evidence_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeUboControlEntryV1 {
    pub validator_id: String,
    pub record: StakeUboControlRecordCommandV1,
}

/// Complete, content-addressed governance request for installing one staged
/// stake-authority view.  It deliberately uses only explicit structs,
/// sequences and unit enums so RLD-WIRE-V1 never inherits map or data-enum
/// behavior from a Serde implementation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StakeAuthorityGovernanceUpdateV1 {
    pub update_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub authority_version: u16,
    pub sequence: u64,
    pub expected_previous_commitment: String,
    pub policy: StakeAuthorityPolicyCommandV1,
    pub candidates: Vec<StakeAuthorityCandidateCommandV1>,
    pub positions: Vec<StakeAuthorityPositionCommandV1>,
    pub ubo_map_version: u16,
    pub ubo_sequence: u64,
    pub ubo_predecessor_commitment: String,
    pub ubo_verifier_set_commitment: String,
    pub ubo_evidence_root: String,
    pub ubo_validators: Vec<StakeUboControlEntryV1>,
    /// Commitment of the exact ledger-owned state the command expects to
    /// create from its certified parent state.
    pub prospective_authority_commitment: String,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl StakeAuthorityGovernanceUpdateV1 {
    pub fn compute_subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-STAKE-AUTHORITY-GOVERNANCE-UPDATE-V1",
            self.update_id.as_bytes(),
            self.zone_id.as_bytes(),
            self.currency_genesis_root.as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
            &self.proposed_height.to_be_bytes(),
            &self.expires_at_height.to_be_bytes(),
            &self.authority_version.to_be_bytes(),
            &self.sequence.to_be_bytes(),
            self.expected_previous_commitment.as_bytes(),
            self.prospective_authority_commitment.as_bytes(),
        ])
    }

    /// Reconstructs the internal authority update only from a canonical
    /// command view.  Multiple command encodings of one semantic view are
    /// rejected rather than silently normalized.
    pub fn to_ledger_update(&self) -> Result<LedgerStakeAuthorityUpdateV1, String> {
        if self
            .candidates
            .windows(2)
            .any(|items| items[0].validator_id >= items[1].validator_id)
        {
            return Err(
                "stake authority candidates are not strictly ordered by validator id".into(),
            );
        }
        if self
            .positions
            .windows(2)
            .any(|items| items[0].position_id >= items[1].position_id)
        {
            return Err("stake authority positions are not strictly ordered by position id".into());
        }
        if self
            .ubo_validators
            .windows(2)
            .any(|items| items[0].validator_id >= items[1].validator_id)
        {
            return Err("stake UBO entries are not strictly ordered by validator id".into());
        }

        let policy = ConsensusStakePolicyV1 {
            policy_version: self.policy.policy_version,
            minimum_self_bond: self.policy.minimum_self_bond,
            minimum_delegation: self.policy.minimum_delegation,
            candidate_maturity_blocks: u128::from(self.policy.candidate_maturity_blocks),
            stake_maturity_blocks: u128::from(self.policy.stake_maturity_blocks),
            evidence_window_blocks: u128::from(self.policy.evidence_window_blocks),
            activation_delay_blocks: u128::from(self.policy.activation_delay_blocks),
            epoch_length_blocks: u128::from(self.policy.epoch_length_blocks),
            maximum_validators: self.policy.maximum_validators,
        };
        let candidates = self
            .candidates
            .iter()
            .map(|candidate| ValidatorCandidateRecord {
                validator_id: candidate.validator_id.clone(),
                owner: candidate.owner.clone(),
                public_key: candidate.public_key.clone(),
                key_era: candidate.key_era,
                registered_height: u128::from(candidate.registered_height),
                exit_height: candidate.exit_height.map(u128::from),
                proof_of_possession: candidate.proof_of_possession.clone(),
            })
            .collect();
        let positions = self
            .positions
            .iter()
            .map(|position| ConsensusStakePosition {
                position_id: position.position_id.clone(),
                kind: match position.position_type {
                    StakePositionTypeV1::SelfBond => ConsensusStakePositionKind::SelfBond {
                        validator_id: position.validator_id.clone(),
                    },
                    StakePositionTypeV1::Delegation => ConsensusStakePositionKind::Delegation {
                        validator_id: position.validator_id.clone(),
                    },
                },
                owner: position.owner.clone(),
                source_coin_id: position.source_coin_id.clone(),
                escrow_coin_id: position.escrow_coin_id.clone(),
                amount: position.amount,
                locked_height: u128::from(position.locked_height),
                committed_through_height: u128::from(position.committed_through_height),
                slash_terms: None,
            })
            .collect();
        let validators = self
            .ubo_validators
            .iter()
            .map(|entry| {
                (
                    entry.validator_id.clone(),
                    UboControlRecord {
                        control_group: entry.record.control_group.clone(),
                        valid_from_height: u128::from(entry.record.valid_from_height),
                        challenge_ends_height: u128::from(entry.record.challenge_ends_height),
                        valid_through_height: u128::from(entry.record.valid_through_height),
                        evidence_hash: entry.record.evidence_hash.clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if validators.len() != self.ubo_validators.len() {
            return Err("stake UBO entries contain duplicate validator ids".into());
        }
        Ok(LedgerStakeAuthorityUpdateV1 {
            authority_version: self.authority_version,
            sequence: self.sequence,
            expected_previous_commitment: self.expected_previous_commitment.clone(),
            policy,
            candidates,
            positions,
            ubo_control: UboControlMap {
                map_version: self.ubo_map_version,
                sequence: self.ubo_sequence,
                predecessor_commitment: self.ubo_predecessor_commitment.clone(),
                verifier_set_commitment: self.ubo_verifier_set_commitment.clone(),
                evidence_root: self.ubo_evidence_root.clone(),
                validators,
            },
        })
    }
}

/// Exact preconditions for persisting the next `DERIVED_ONLY` stake Epoch.
/// The command cannot choose membership; it can only request the deterministic
/// next record from one already-staged authority and one certified parent root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeriveNextStakeEpochRequestV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub expected_consensus_epoch: u64,
    pub expected_snapshot_height: u64,
    pub expected_snapshot_state_root: String,
}

pub const DERIVE_NEXT_STAKE_EPOCH_ACTION_V2: &str = "DERIVE_NEXT_STAKE_EPOCH_V2";
pub const DERIVE_NEXT_STAKE_EPOCH_RESOURCE_OPERATION_V2: &str =
    "DERIVE_NEXT_STAKE_EPOCH_RESOURCE_OPERATION_V2";

/// Resource-bound deterministic Epoch derivation. `payer` authorizes the
/// exact output commitment and a separately signed sponsor envelope funds the
/// fee and retention bond. Membership is still derived exclusively from the
/// staged authority; neither signer can supply validators or weights.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeriveNextStakeEpochRequestV2 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub expected_consensus_epoch: u64,
    pub expected_snapshot_height: u64,
    pub expected_snapshot_state_root: String,
    pub expected_derived_record_hash: String,
    pub payer: String,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

impl DeriveNextStakeEpochRequestV2 {
    fn core_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.request_id.as_bytes().to_vec(),
            self.zone_id.as_bytes().to_vec(),
            self.currency_genesis_root.as_bytes().to_vec(),
            self.protocol_era.to_be_bytes().to_vec(),
            self.crypto_era.to_be_bytes().to_vec(),
            self.proposed_height.to_be_bytes().to_vec(),
            self.expires_at_height.to_be_bytes().to_vec(),
            self.expected_authority_sequence.to_be_bytes().to_vec(),
            self.expected_authority_commitment.as_bytes().to_vec(),
            self.expected_consensus_epoch.to_be_bytes().to_vec(),
            self.expected_snapshot_height.to_be_bytes().to_vec(),
            self.expected_snapshot_state_root.as_bytes().to_vec(),
            self.expected_derived_record_hash.as_bytes().to_vec(),
            self.payer.as_bytes().to_vec(),
        ]
    }

    pub fn resource_operation_hash(&self) -> String {
        let fields = self.core_fields();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(DERIVE_NEXT_STAKE_EPOCH_RESOURCE_OPERATION_V2, &field_refs)
    }

    pub fn payload_hash(&self) -> String {
        let resource_authorization_commitment = hash_parts(&[
            b"RLD-STAKE-RESOURCE-SPONSOR-AUTHORIZATION-COMMITMENT-V1",
            &self.resource_envelope.authorization.signing_bytes(),
            self.resource_envelope.authorization.signature.as_bytes(),
        ]);
        let mut fields = self.core_fields();
        fields.extend([
            self.resource_envelope
                .resource_policy_sequence
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_policy_commitment
                .as_bytes()
                .to_vec(),
            self.resource_envelope.sponsor.as_bytes().to_vec(),
            self.resource_envelope.funding_coin_id.as_bytes().to_vec(),
            self.resource_envelope
                .max_resource_fee
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .max_state_bond
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .lease_end_height
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_subject_hash
                .as_bytes()
                .to_vec(),
            resource_authorization_commitment.as_bytes().to_vec(),
        ]);
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(DERIVE_NEXT_STAKE_EPOCH_ACTION_V2, &field_refs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeriveNextStakeEpochOutcomeV2 {
    pub epoch: LedgerDerivedStakeEpochV1,
    pub resource_key: String,
    pub bond_id: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub initial_bond_record_hash: String,
}

pub const RENEW_STAKE_STATE_RESOURCE_BOND_ACTION_V1: &str = "RENEW_STAKE_STATE_RESOURCE_BOND_V1";

/// A deliberately narrow extension of one existing resource-bond history.
/// The request contains no resource usage and no mutable copy of the covered
/// object. Consensus derives both the old persistent footprint and the new
/// renewal-record footprint from retained state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenewStakeStateResourceBondRequestV1 {
    pub renewal_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub resource_key: String,
    pub resource_kind: StakeStateResourceKindV1,
    pub resource_owner: String,
    pub expected_bond_id: String,
    pub expected_initial_bond_record_hash: String,
    pub expected_previous_renewal_hash: String,
    pub expected_current_lease_end_height: u64,
    pub new_lease_end_height: u64,
    pub resource_policy_sequence: u64,
    pub resource_policy_commitment: String,
    pub sponsor: String,
    pub funding_coin_id: String,
    pub max_resource_fee: Amount,
    pub max_additional_bond: Amount,
    pub authorization: SignedActionAuthorization,
}

impl RenewStakeStateResourceBondRequestV1 {
    pub fn payload_hash(&self) -> String {
        action_payload_hash(
            RENEW_STAKE_STATE_RESOURCE_BOND_ACTION_V1,
            &[
                self.renewal_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                self.resource_key.as_bytes(),
                self.resource_kind.wire_name().as_bytes(),
                self.resource_owner.as_bytes(),
                self.expected_bond_id.as_bytes(),
                self.expected_initial_bond_record_hash.as_bytes(),
                self.expected_previous_renewal_hash.as_bytes(),
                &self.expected_current_lease_end_height.to_be_bytes(),
                &self.new_lease_end_height.to_be_bytes(),
                &self.resource_policy_sequence.to_be_bytes(),
                self.resource_policy_commitment.as_bytes(),
                self.sponsor.as_bytes(),
                self.funding_coin_id.as_bytes(),
                &self.max_resource_fee.0.to_be_bytes(),
                &self.max_additional_bond.0.to_be_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenewStakeStateResourceBondOutcomeV1 {
    pub renewal_id: String,
    pub resource_key: String,
    pub previous_renewal_hash: String,
    pub renewal_record_hash: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub additional_bond: Amount,
    pub previous_lease_end_height: u64,
    pub new_lease_end_height: u64,
}

/// Owner-authorized request to consume one spendable Coin and create one
/// stake-specific reserved escrow.  The exact authority predecessor is bound
/// so a signature cannot be replayed after governance changes the candidate
/// or stake policy view.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockConsensusStakeRequestV1 {
    pub position_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_type: StakePositionTypeV1,
    pub validator_id: String,
    pub owner: String,
    pub source_coin_id: String,
    pub amount: Amount,
    pub committed_through_height: u64,
    pub authorization: SignedActionAuthorization,
}

pub const LOCK_CONSENSUS_STAKE_ACTION_V1: &str = "LOCK_CONSENSUS_STAKE_V1";

impl LockConsensusStakeRequestV1 {
    pub fn payload_hash(&self) -> String {
        action_payload_hash(
            LOCK_CONSENSUS_STAKE_ACTION_V1,
            &[
                self.position_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.position_type.wire_name().as_bytes(),
                self.validator_id.as_bytes(),
                self.owner.as_bytes(),
                self.source_coin_id.as_bytes(),
                &self.amount.0.to_be_bytes(),
                &self.committed_through_height.to_be_bytes(),
            ],
        )
    }
}

pub const LOCK_CONSENSUS_STAKE_ACTION_V2: &str = "LOCK_CONSENSUS_STAKE_V2";

/// New stake admission with a second, independently retained owner signature
/// accepting the protocol-fixed objective-fault slash terms. The legacy V1
/// command remains decodable for exit/migration compatibility but cannot add
/// weight under a derivation-version-2 policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockConsensusStakeRequestV2 {
    pub position_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_type: StakePositionTypeV1,
    pub validator_id: String,
    pub owner: String,
    pub source_coin_id: String,
    pub amount: Amount,
    pub committed_through_height: u64,
    pub slash_terms_authorization: SignedActionAuthorization,
    pub authorization: SignedActionAuthorization,
}

impl LockConsensusStakeRequestV2 {
    pub fn slash_terms_payload_hash(&self) -> String {
        consensus_stake_slash_terms_payload_hash_v2(
            &self.position_id,
            &match self.position_type {
                StakePositionTypeV1::SelfBond => ConsensusStakePositionKind::SelfBond {
                    validator_id: self.validator_id.clone(),
                },
                StakePositionTypeV1::Delegation => ConsensusStakePositionKind::Delegation {
                    validator_id: self.validator_id.clone(),
                },
            },
            &self.owner,
            &self.source_coin_id,
            self.amount,
            u128::from(self.committed_through_height),
            &ConsensusStakeSlashPolicyV2::protocol_v2(),
        )
    }

    pub fn payload_hash(&self) -> String {
        let slash_terms_authorization_commitment = hash_parts(&[
            b"RLD-SIGNED-ACTION-AUTHORIZATION-COMMITMENT-V2",
            &self.slash_terms_authorization.signing_bytes(),
            self.slash_terms_authorization.signature.as_bytes(),
        ]);
        action_payload_hash(
            LOCK_CONSENSUS_STAKE_ACTION_V2,
            &[
                self.position_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.position_type.wire_name().as_bytes(),
                self.validator_id.as_bytes(),
                self.owner.as_bytes(),
                self.source_coin_id.as_bytes(),
                &self.amount.0.to_be_bytes(),
                &self.committed_through_height.to_be_bytes(),
                self.slash_terms_payload_hash().as_bytes(),
                slash_terms_authorization_commitment.as_bytes(),
            ],
        )
    }
}

pub const LOCK_CONSENSUS_STAKE_ACTION_V3: &str = "LOCK_CONSENSUS_STAKE_V3";
pub const LOCK_CONSENSUS_STAKE_RESOURCE_OPERATION_V3: &str =
    "LOCK_CONSENSUS_STAKE_RESOURCE_OPERATION_V3";

/// Resource-bound stake admission. The stake principal and its change are
/// derived only from `source_coin_id`; a separate sponsor-funded Coin pays the
/// deterministic resource fee and state bond. The command carries no caller-
/// supplied usage counters.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockConsensusStakeRequestV3 {
    pub position_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_type: StakePositionTypeV1,
    pub validator_id: String,
    pub owner: String,
    pub source_coin_id: String,
    pub amount: Amount,
    pub committed_through_height: u64,
    pub slash_terms_authorization: SignedActionAuthorization,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

impl LockConsensusStakeRequestV3 {
    pub fn slash_terms_payload_hash(&self) -> String {
        consensus_stake_slash_terms_payload_hash_v2(
            &self.position_id,
            &match self.position_type {
                StakePositionTypeV1::SelfBond => ConsensusStakePositionKind::SelfBond {
                    validator_id: self.validator_id.clone(),
                },
                StakePositionTypeV1::Delegation => ConsensusStakePositionKind::Delegation {
                    validator_id: self.validator_id.clone(),
                },
            },
            &self.owner,
            &self.source_coin_id,
            self.amount,
            u128::from(self.committed_through_height),
            &ConsensusStakeSlashPolicyV2::protocol_v2(),
        )
    }

    fn core_fields(&self) -> Vec<Vec<u8>> {
        let slash_terms_authorization_commitment = hash_parts(&[
            b"RLD-SIGNED-ACTION-AUTHORIZATION-COMMITMENT-V2",
            &self.slash_terms_authorization.signing_bytes(),
            self.slash_terms_authorization.signature.as_bytes(),
        ]);
        vec![
            self.position_id.as_bytes().to_vec(),
            self.zone_id.as_bytes().to_vec(),
            self.currency_genesis_root.as_bytes().to_vec(),
            self.protocol_era.to_be_bytes().to_vec(),
            self.crypto_era.to_be_bytes().to_vec(),
            self.proposed_height.to_be_bytes().to_vec(),
            self.expires_at_height.to_be_bytes().to_vec(),
            self.expected_authority_sequence.to_be_bytes().to_vec(),
            self.expected_authority_commitment.as_bytes().to_vec(),
            self.position_type.wire_name().as_bytes().to_vec(),
            self.validator_id.as_bytes().to_vec(),
            self.owner.as_bytes().to_vec(),
            self.source_coin_id.as_bytes().to_vec(),
            self.amount.0.to_be_bytes().to_vec(),
            self.committed_through_height.to_be_bytes().to_vec(),
            self.slash_terms_payload_hash().as_bytes().to_vec(),
            slash_terms_authorization_commitment.as_bytes().to_vec(),
        ]
    }

    pub fn resource_operation_hash(&self) -> String {
        let fields = self.core_fields();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(LOCK_CONSENSUS_STAKE_RESOURCE_OPERATION_V3, &field_refs)
    }

    pub fn payload_hash(&self) -> String {
        let resource_authorization_commitment = hash_parts(&[
            b"RLD-STAKE-RESOURCE-SPONSOR-AUTHORIZATION-COMMITMENT-V1",
            &self.resource_envelope.authorization.signing_bytes(),
            self.resource_envelope.authorization.signature.as_bytes(),
        ]);
        let mut fields = self.core_fields();
        fields.extend([
            self.resource_envelope
                .resource_policy_sequence
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_policy_commitment
                .as_bytes()
                .to_vec(),
            self.resource_envelope.sponsor.as_bytes().to_vec(),
            self.resource_envelope.funding_coin_id.as_bytes().to_vec(),
            self.resource_envelope
                .max_resource_fee
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .max_state_bond
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .lease_end_height
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_subject_hash
                .as_bytes()
                .to_vec(),
            resource_authorization_commitment.as_bytes().to_vec(),
        ]);
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(LOCK_CONSENSUS_STAKE_ACTION_V3, &field_refs)
    }
}

/// Immutable receipt for a resource-bound stake admission. The position and
/// the initial resource-bond record are sufficient for exact replay even after
/// later lifecycle transitions extend their respective histories.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockConsensusStakeOutcomeV3 {
    pub position: ConsensusStakePosition,
    pub resource_key: String,
    pub bond_id: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub initial_bond_record_hash: String,
}

pub const MIGRATE_CONSENSUS_STAKE_RESOURCE_ACTION_V1: &str = "MIGRATE_CONSENSUS_STAKE_RESOURCE_V1";
pub const MIGRATE_CONSENSUS_STAKE_RESOURCE_OPERATION_V1: &str =
    "MIGRATE_CONSENSUS_STAKE_RESOURCE_OPERATION_V1";

/// Separately funded migration of one exact, already slashable position from
/// the finite inventory frozen when the first resource policy activated. The
/// stake principal, authority record and escrow Coin are not modified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateConsensusStakeResourceRequestV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_id: String,
    pub escrow_coin_id: String,
    pub owner: String,
    pub expected_position_commitment: String,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

impl MigrateConsensusStakeResourceRequestV1 {
    fn core_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.request_id.as_bytes().to_vec(),
            self.zone_id.as_bytes().to_vec(),
            self.currency_genesis_root.as_bytes().to_vec(),
            self.protocol_era.to_be_bytes().to_vec(),
            self.crypto_era.to_be_bytes().to_vec(),
            self.proposed_height.to_be_bytes().to_vec(),
            self.expires_at_height.to_be_bytes().to_vec(),
            self.expected_authority_sequence.to_be_bytes().to_vec(),
            self.expected_authority_commitment.as_bytes().to_vec(),
            self.position_id.as_bytes().to_vec(),
            self.escrow_coin_id.as_bytes().to_vec(),
            self.owner.as_bytes().to_vec(),
            self.expected_position_commitment.as_bytes().to_vec(),
        ]
    }

    pub fn resource_operation_hash(&self) -> String {
        let fields = self.core_fields();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(MIGRATE_CONSENSUS_STAKE_RESOURCE_OPERATION_V1, &field_refs)
    }

    pub fn payload_hash(&self) -> String {
        let resource_authorization_commitment = hash_parts(&[
            b"RLD-STAKE-RESOURCE-SPONSOR-AUTHORIZATION-COMMITMENT-V1",
            &self.resource_envelope.authorization.signing_bytes(),
            self.resource_envelope.authorization.signature.as_bytes(),
        ]);
        let mut fields = self.core_fields();
        fields.extend([
            self.resource_envelope
                .resource_policy_sequence
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_policy_commitment
                .as_bytes()
                .to_vec(),
            self.resource_envelope.sponsor.as_bytes().to_vec(),
            self.resource_envelope.funding_coin_id.as_bytes().to_vec(),
            self.resource_envelope
                .max_resource_fee
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .max_state_bond
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .lease_end_height
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_subject_hash
                .as_bytes()
                .to_vec(),
            resource_authorization_commitment.as_bytes().to_vec(),
        ]);
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(MIGRATE_CONSENSUS_STAKE_RESOURCE_ACTION_V1, &field_refs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateConsensusStakeResourceOutcomeV1 {
    pub position: ConsensusStakePosition,
    pub resource_key: String,
    pub bond_id: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub initial_bond_record_hash: String,
}

pub const MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_ACTION_V1: &str =
    "MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_V1";
pub const MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_OPERATION_V1: &str =
    "MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_OPERATION_V1";

/// Separately funded migration of one exact candidate from the finite
/// inventory frozen at resource-policy activation. It adds no candidate and
/// changes no authority or runtime membership field.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateConsensusCandidateResourceRequestV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub registered_height: u64,
    pub exit_height: Option<u64>,
    pub proof_of_possession: String,
    pub expected_candidate_commitment: String,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

impl MigrateConsensusCandidateResourceRequestV1 {
    fn core_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.request_id.as_bytes().to_vec(),
            self.zone_id.as_bytes().to_vec(),
            self.currency_genesis_root.as_bytes().to_vec(),
            self.protocol_era.to_be_bytes().to_vec(),
            self.crypto_era.to_be_bytes().to_vec(),
            self.proposed_height.to_be_bytes().to_vec(),
            self.expires_at_height.to_be_bytes().to_vec(),
            self.expected_authority_sequence.to_be_bytes().to_vec(),
            self.expected_authority_commitment.as_bytes().to_vec(),
            self.validator_id.as_bytes().to_vec(),
            self.owner.as_bytes().to_vec(),
            self.public_key.as_bytes().to_vec(),
            self.key_era.to_be_bytes().to_vec(),
            self.registered_height.to_be_bytes().to_vec(),
            self.exit_height.unwrap_or_default().to_be_bytes().to_vec(),
            vec![u8::from(self.exit_height.is_some())],
            self.proof_of_possession.as_bytes().to_vec(),
            self.expected_candidate_commitment.as_bytes().to_vec(),
        ]
    }

    pub fn resource_operation_hash(&self) -> String {
        let fields = self.core_fields();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(
            MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_OPERATION_V1,
            &field_refs,
        )
    }

    pub fn payload_hash(&self) -> String {
        let resource_authorization_commitment = hash_parts(&[
            b"RLD-STAKE-RESOURCE-SPONSOR-AUTHORIZATION-COMMITMENT-V1",
            &self.resource_envelope.authorization.signing_bytes(),
            self.resource_envelope.authorization.signature.as_bytes(),
        ]);
        let mut fields = self.core_fields();
        fields.extend([
            self.resource_envelope
                .resource_policy_sequence
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_policy_commitment
                .as_bytes()
                .to_vec(),
            self.resource_envelope.sponsor.as_bytes().to_vec(),
            self.resource_envelope.funding_coin_id.as_bytes().to_vec(),
            self.resource_envelope
                .max_resource_fee
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .max_state_bond
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .lease_end_height
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_subject_hash
                .as_bytes()
                .to_vec(),
            resource_authorization_commitment.as_bytes().to_vec(),
        ]);
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(MIGRATE_CONSENSUS_CANDIDATE_RESOURCE_ACTION_V1, &field_refs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateConsensusCandidateResourceOutcomeV1 {
    pub candidate: ValidatorCandidateRecord,
    pub resource_key: String,
    pub bond_id: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub initial_bond_record_hash: String,
}

pub const MIGRATE_CONSENSUS_STAKE_SLASH_TERMS_ACTION_V2: &str =
    "MIGRATE_CONSENSUS_STAKE_SLASH_TERMS_V2";

/// Owner-authorized migration of an exact active legacy position. No Coin or
/// amount changes; only the separately signed v2 slash terms are attached and
/// a new authority predecessor is committed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrateConsensusStakeSlashTermsV2 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_id: String,
    pub escrow_coin_id: String,
    pub owner: String,
    pub slash_terms_authorization: SignedActionAuthorization,
    pub authorization: SignedActionAuthorization,
}

impl MigrateConsensusStakeSlashTermsV2 {
    pub fn payload_hash(&self, position: &ConsensusStakePosition) -> String {
        let slash_terms_authorization_commitment = hash_parts(&[
            b"RLD-SIGNED-ACTION-AUTHORIZATION-COMMITMENT-V2",
            &self.slash_terms_authorization.signing_bytes(),
            self.slash_terms_authorization.signature.as_bytes(),
        ]);
        action_payload_hash(
            MIGRATE_CONSENSUS_STAKE_SLASH_TERMS_ACTION_V2,
            &[
                self.request_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.position_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                self.owner.as_bytes(),
                position.slash_terms_payload_hash_v2().as_bytes(),
                slash_terms_authorization_commitment.as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusStakeUnbondStatusV1 {
    Pending,
    Completed,
    FullySlashed,
}

impl ConsensusStakeUnbondStatusV1 {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Completed => "COMPLETED",
            Self::FullySlashed => "FULLY_SLASHED",
        }
    }
}

/// Immutable request facts plus the completion state for one delayed stake
/// withdrawal. The embedded position preserves the exact historical escrow
/// after it is removed from the active registry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeUnbondRecordV1 {
    pub request_id: String,
    pub position: ConsensusStakePosition,
    pub owner: String,
    pub beneficiary: String,
    pub requested_height: u64,
    pub withdraw_after_height: u64,
    pub request_commitment: String,
    pub status: ConsensusStakeUnbondStatusV1,
    pub completion_id: Option<String>,
    pub completed_height: Option<u64>,
    pub payout_coin_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_id: Option<String>,
    #[serde(default, skip_serializing_if = "amount_is_zero")]
    pub slashed_amount: Amount,
}

impl ConsensusStakeUnbondRecordV1 {
    pub fn compute_request_commitment(&self) -> String {
        let (position_type, validator_id) = match &self.position.kind {
            ConsensusStakePositionKind::SelfBond { validator_id } => {
                (StakePositionTypeV1::SelfBond, validator_id)
            }
            ConsensusStakePositionKind::Delegation { validator_id } => {
                (StakePositionTypeV1::Delegation, validator_id)
            }
        };
        hash_parts(&[
            b"RLD-CONSENSUS-STAKE-UNBOND-REQUEST-RECORD-V1",
            self.request_id.as_bytes(),
            self.position.position_id.as_bytes(),
            position_type.wire_name().as_bytes(),
            validator_id.as_bytes(),
            self.position.owner.as_bytes(),
            self.position.source_coin_id.as_bytes(),
            self.position.escrow_coin_id.as_bytes(),
            &self.position.amount.0.to_be_bytes(),
            &self.position.locked_height.to_be_bytes(),
            &self.position.committed_through_height.to_be_bytes(),
            self.owner.as_bytes(),
            self.beneficiary.as_bytes(),
            &self.requested_height.to_be_bytes(),
            &self.withdraw_after_height.to_be_bytes(),
        ])
    }
}

/// Permissionless, evidence-bound request to slash one exact historical
/// liability. The amount is not caller-selected: it is derived from the
/// owner-signed protocol policy retained in the liability.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlashConsensusStakeV1 {
    pub slash_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub consensus_epoch: u64,
    pub derived_epoch_record_hash: String,
    pub position_id: String,
    pub escrow_coin_id: String,
    pub expected_position_amount: Amount,
    pub liability_commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_unbond_request_commitment: Option<String>,
    pub evidence_hash: String,
    pub evidence: ConsensusStakeSlashEvidenceV1,
}

/// Immutable audit record for a completed consensus-stake slash. Version 1
/// supports only the protocol-fixed 100% objective-fault penalties, so there
/// is no caller-controlled remainder or reporter reward.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusStakeSlashRecordV1 {
    pub slash_id: String,
    pub evidence_kind: ConsensusStakeSlashEvidenceKindV1,
    pub evidence_hash: String,
    /// Full content-addressed signed evidence is retained so checkpoints and
    /// audit bundles can re-verify a slash without a separate history server.
    pub evidence: ConsensusStakeSlashEvidenceV1,
    pub consensus_epoch: u64,
    pub derived_epoch_record_hash: String,
    pub liability_commitment: String,
    pub position: ConsensusStakePosition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unbond_request_commitment: Option<String>,
    pub slash_bps: u16,
    pub slashed_amount: Amount,
    pub source_escrow_coin_id: String,
    pub safety_pool_coin_id: String,
    pub applied_height: u64,
    pub record_hash: String,
}

/// Single-use key for one exact evidence/liability pair. The same objective
/// validator-fault evidence may cover several independently frozen stake
/// liabilities, while one liability must never be slashed twice.
pub fn consensus_stake_slash_nullifier_v1(
    evidence_hash: &str,
    liability_commitment: &str,
) -> String {
    hash_parts(&[
        b"RLD-CONSENSUS-STAKE-SLASH-NULLIFIER-V1",
        evidence_hash.as_bytes(),
        liability_commitment.as_bytes(),
    ])
}

impl ConsensusStakeSlashRecordV1 {
    pub fn compute_record_hash(&self) -> String {
        hash_parts(&[
            b"RLD-CONSENSUS-STAKE-SLASH-RECORD-V1",
            self.slash_id.as_bytes(),
            self.evidence_kind.wire_name().as_bytes(),
            self.evidence_hash.as_bytes(),
            &self.consensus_epoch.to_be_bytes(),
            self.derived_epoch_record_hash.as_bytes(),
            self.liability_commitment.as_bytes(),
            self.position.position_id.as_bytes(),
            self.position.escrow_coin_id.as_bytes(),
            &self.position.amount.0.to_be_bytes(),
            self.unbond_request_commitment
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            &self.slash_bps.to_be_bytes(),
            &self.slashed_amount.0.to_be_bytes(),
            self.source_escrow_coin_id.as_bytes(),
            self.safety_pool_coin_id.as_bytes(),
            &self.applied_height.to_be_bytes(),
        ])
    }
}

/// Owner-authorized request to stop one registered position from entering new
/// Epochs and schedule its escrow for withdrawal after all frozen obligations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestConsensusStakeUnbondV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub position_id: String,
    pub escrow_coin_id: String,
    pub owner: String,
    pub beneficiary: String,
    pub requested_withdraw_after_height: u64,
    pub authorization: SignedActionAuthorization,
}

pub const REQUEST_CONSENSUS_STAKE_UNBOND_ACTION_V1: &str = "REQUEST_CONSENSUS_STAKE_UNBOND_V1";

impl RequestConsensusStakeUnbondV1 {
    pub fn payload_hash(&self) -> String {
        action_payload_hash(
            REQUEST_CONSENSUS_STAKE_UNBOND_ACTION_V1,
            &[
                self.request_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.position_id.as_bytes(),
                self.escrow_coin_id.as_bytes(),
                self.owner.as_bytes(),
                self.beneficiary.as_bytes(),
                &self.requested_withdraw_after_height.to_be_bytes(),
            ],
        )
    }
}

/// Permissionless-at-maturity completion request. Consensus authenticates the
/// transition, while the immutable pending commitment fixes the beneficiary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompleteConsensusStakeUnbondV1 {
    pub completion_id: String,
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_unbond_request_commitment: String,
    pub beneficiary: String,
}

/// Owner- and consensus-key-authorized request to append one validator
/// candidate to the staged authority. The ledger assigns the registration
/// height, so a caller cannot backdate candidate maturity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterConsensusValidatorRequestV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub proof_of_possession: String,
    pub authorization: SignedActionAuthorization,
}

pub const REGISTER_CONSENSUS_VALIDATOR_ACTION_V1: &str = "REGISTER_CONSENSUS_VALIDATOR_V1";

impl RegisterConsensusValidatorRequestV1 {
    pub fn payload_hash(&self) -> String {
        action_payload_hash(
            REGISTER_CONSENSUS_VALIDATOR_ACTION_V1,
            &[
                self.request_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.validator_id.as_bytes(),
                self.owner.as_bytes(),
                self.public_key.as_bytes(),
                &self.key_era.to_be_bytes(),
                self.proof_of_possession.as_bytes(),
            ],
        )
    }
}

/// Resource-bound candidate registration. The caller does not provide usage
/// counters: consensus derives them from the canonical command and the frozen
/// candidate footprint before verifying the sponsor authorization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterConsensusValidatorRequestV2 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub proof_of_possession: String,
    pub resource_envelope: StakeStateResourceEnvelopeV1,
    pub authorization: SignedActionAuthorization,
}

pub const REGISTER_CONSENSUS_VALIDATOR_ACTION_V2: &str = "REGISTER_CONSENSUS_VALIDATOR_V2";
pub const REGISTER_CONSENSUS_VALIDATOR_RESOURCE_OPERATION_V2: &str =
    "REGISTER_CONSENSUS_VALIDATOR_RESOURCE_OPERATION_V2";

impl RegisterConsensusValidatorRequestV2 {
    fn core_fields(&self) -> Vec<Vec<u8>> {
        vec![
            self.request_id.as_bytes().to_vec(),
            self.zone_id.as_bytes().to_vec(),
            self.currency_genesis_root.as_bytes().to_vec(),
            self.protocol_era.to_be_bytes().to_vec(),
            self.crypto_era.to_be_bytes().to_vec(),
            self.proposed_height.to_be_bytes().to_vec(),
            self.expires_at_height.to_be_bytes().to_vec(),
            self.expected_authority_sequence.to_be_bytes().to_vec(),
            self.expected_authority_commitment.as_bytes().to_vec(),
            self.validator_id.as_bytes().to_vec(),
            self.owner.as_bytes().to_vec(),
            self.public_key.as_bytes().to_vec(),
            self.key_era.to_be_bytes().to_vec(),
            self.proof_of_possession.as_bytes().to_vec(),
        ]
    }

    pub fn resource_operation_hash(&self) -> String {
        let fields = self.core_fields();
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(
            REGISTER_CONSENSUS_VALIDATOR_RESOURCE_OPERATION_V2,
            &field_refs,
        )
    }

    pub fn payload_hash(&self) -> String {
        let resource_authorization_commitment = hash_parts(&[
            b"RLD-STAKE-RESOURCE-SPONSOR-AUTHORIZATION-COMMITMENT-V1",
            &self.resource_envelope.authorization.signing_bytes(),
            self.resource_envelope.authorization.signature.as_bytes(),
        ]);
        let mut fields = self.core_fields();
        fields.extend([
            self.resource_envelope
                .resource_policy_sequence
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_policy_commitment
                .as_bytes()
                .to_vec(),
            self.resource_envelope.sponsor.as_bytes().to_vec(),
            self.resource_envelope.funding_coin_id.as_bytes().to_vec(),
            self.resource_envelope
                .max_resource_fee
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .max_state_bond
                .0
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .lease_end_height
                .to_be_bytes()
                .to_vec(),
            self.resource_envelope
                .resource_subject_hash
                .as_bytes()
                .to_vec(),
            resource_authorization_commitment.as_bytes().to_vec(),
        ]);
        let field_refs = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        action_payload_hash(REGISTER_CONSENSUS_VALIDATOR_ACTION_V2, &field_refs)
    }
}

/// Immutable replay result for a resource-bound candidate admission. Mutable
/// bond lifecycle fields are intentionally excluded; the initial record hash
/// remains derivable from the retained bond record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterConsensusValidatorOutcomeV2 {
    pub candidate: ValidatorCandidateRecord,
    pub resource_key: String,
    pub bond_id: String,
    pub bond_coin_id: String,
    pub charged_fee: Amount,
    pub locked_bond: Amount,
    pub initial_bond_record_hash: String,
}

/// Owner- and consensus-key-authorized request to set the one-way exit height
/// of an existing candidate. The updated proof of possession signs the exact
/// candidate record including that exit height.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExitConsensusValidatorRequestV1 {
    pub request_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub proposed_height: u64,
    pub expires_at_height: u64,
    pub expected_authority_sequence: u64,
    pub expected_authority_commitment: String,
    pub validator_id: String,
    pub owner: String,
    pub public_key: String,
    pub key_era: u64,
    pub registered_height: u64,
    pub exit_height: u64,
    pub proof_of_possession: String,
    pub authorization: SignedActionAuthorization,
}

pub const EXIT_CONSENSUS_VALIDATOR_ACTION_V1: &str = "EXIT_CONSENSUS_VALIDATOR_V1";

impl ExitConsensusValidatorRequestV1 {
    pub fn payload_hash(&self) -> String {
        action_payload_hash(
            EXIT_CONSENSUS_VALIDATOR_ACTION_V1,
            &[
                self.request_id.as_bytes(),
                self.zone_id.as_bytes(),
                self.currency_genesis_root.as_bytes(),
                &self.protocol_era.to_be_bytes(),
                &self.crypto_era.to_be_bytes(),
                &self.proposed_height.to_be_bytes(),
                &self.expires_at_height.to_be_bytes(),
                &self.expected_authority_sequence.to_be_bytes(),
                self.expected_authority_commitment.as_bytes(),
                self.validator_id.as_bytes(),
                self.owner.as_bytes(),
                self.public_key.as_bytes(),
                &self.key_era.to_be_bytes(),
                &self.registered_height.to_be_bytes(),
                &self.exit_height.to_be_bytes(),
                self.proof_of_possession.as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkHeartbeatV1 {
    pub heartbeat_id: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub parent_height: u64,
    pub note_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusCommand {
    LocalPayment(UniversalPaymentIntent),
    ExportPayment {
        intent: UniversalPaymentIntent,
        transport: TransportClass,
    },
    ImportCapsule(Box<TransitCapsule>),
    FinalizeExport(DestinationImportReceipt),
    SubmitValueRiskPolicyUpdate(Box<ValueRiskPolicyUpdate>),
    ActivatePendingValueRiskPolicy,
    Production(Box<ProductionCommand>),
    SubmitStakeAuthorityUpdate(Box<StakeAuthorityGovernanceUpdateV1>),
    DeriveNextStakeEpoch(Box<DeriveNextStakeEpochRequestV1>),
    LockConsensusStake(Box<LockConsensusStakeRequestV1>),
    RegisterConsensusValidator(Box<RegisterConsensusValidatorRequestV1>),
    RegisterConsensusValidatorV2(Box<RegisterConsensusValidatorRequestV2>),
    ExitConsensusValidator(Box<ExitConsensusValidatorRequestV1>),
    RequestConsensusStakeUnbond(Box<RequestConsensusStakeUnbondV1>),
    CompleteConsensusStakeUnbond(Box<CompleteConsensusStakeUnbondV1>),
    LockConsensusStakeV2(Box<LockConsensusStakeRequestV2>),
    MigrateConsensusStakeSlashTerms(Box<MigrateConsensusStakeSlashTermsV2>),
    SlashConsensusStake(Box<SlashConsensusStakeV1>),
    ProposeStakeStateResourcePolicy(Box<ProposeStakeStateResourcePolicyV1>),
    ActivateStakeStateResourcePolicy(Box<ActivateStakeStateResourcePolicyV1>),
    LockConsensusStakeV3(Box<LockConsensusStakeRequestV3>),
    MigrateConsensusStakeResource(Box<MigrateConsensusStakeResourceRequestV1>),
    MigrateConsensusCandidateResource(Box<MigrateConsensusCandidateResourceRequestV1>),
    DeriveNextStakeEpochV2(Box<DeriveNextStakeEpochRequestV2>),
    RenewStakeStateResourceBond(Box<RenewStakeStateResourceBondRequestV1>),
    /// Assetless permissionless-admission checkpoint. Its proof is committed
    /// directly as schema 0x1071 under top-level command tag 28. Pure Ledger
    /// dispatch cannot execute this command: a node must supply the exact
    /// locally retained Admission history through the authenticated external
    /// execution path.
    CommitAdmissionCheckpoint(Box<AdmissionCheckpointProofV1>),
    NetworkHeartbeat(NetworkHeartbeatV1),
    ScheduleUpgrade(Box<crate::genesis::upgrade_wire::ScheduleUpgradeV1>),
    ActivateUpgrade(Box<crate::genesis::upgrade_wire::ActivateUpgradeV1>),
}

impl ConsensusCommand {
    pub fn command_hash(&self) -> String {
        match self {
            Self::LocalPayment(intent) => {
                let signing_bytes = intent.signing_bytes();
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-LOCAL-PAYMENT-V1",
                    &signing_bytes,
                    intent.signature.as_bytes(),
                ])
            }
            Self::ExportPayment { intent, transport } => {
                let signing_bytes = intent.signing_bytes();
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-EXPORT-PAYMENT-V1",
                    &signing_bytes,
                    intent.signature.as_bytes(),
                    transport.wire_name().as_bytes(),
                ])
            }
            Self::ImportCapsule(capsule) => {
                let encoded = serde_json::to_vec(capsule)
                    .expect("TransitCapsule serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-IMPORT-CAPSULE-V1", &encoded])
            }
            Self::FinalizeExport(receipt) => {
                let encoded = serde_json::to_vec(receipt)
                    .expect("DestinationImportReceipt serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-FINALIZE-EXPORT-V1", &encoded])
            }
            Self::SubmitValueRiskPolicyUpdate(update) => {
                let encoded = serde_json::to_vec(update)
                    .expect("ValueRiskPolicyUpdate serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-VALUE-RISK-UPDATE-V1", &encoded])
            }
            Self::ActivatePendingValueRiskPolicy => {
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-VALUE-RISK-ACTIVATE-V1"])
            }
            Self::Production(command) => {
                let encoded = serde_json::to_vec(command)
                    .expect("ProductionCommand serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-PRODUCTION-V1", &encoded])
            }
            Self::SubmitStakeAuthorityUpdate(update) => {
                let encoded = serde_json::to_vec(update)
                    .expect("StakeAuthorityGovernanceUpdateV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-STAKE-AUTHORITY-UPDATE-V1", &encoded])
            }
            Self::DeriveNextStakeEpoch(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("DeriveNextStakeEpochRequestV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-DERIVE-STAKE-EPOCH-V1", &encoded])
            }
            Self::LockConsensusStake(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("LockConsensusStakeRequestV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-LOCK-STAKE-V1", &encoded])
            }
            Self::RegisterConsensusValidator(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("RegisterConsensusValidatorRequestV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-REGISTER-VALIDATOR-V1", &encoded])
            }
            Self::RegisterConsensusValidatorV2(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("RegisterConsensusValidatorRequestV2 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-REGISTER-VALIDATOR-V2", &encoded])
            }
            Self::ExitConsensusValidator(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("ExitConsensusValidatorRequestV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-EXIT-VALIDATOR-V1", &encoded])
            }
            Self::RequestConsensusStakeUnbond(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("RequestConsensusStakeUnbondV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-REQUEST-STAKE-UNBOND-V1", &encoded])
            }
            Self::CompleteConsensusStakeUnbond(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("CompleteConsensusStakeUnbondV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-COMPLETE-STAKE-UNBOND-V1", &encoded])
            }
            Self::LockConsensusStakeV2(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("LockConsensusStakeRequestV2 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-LOCK-STAKE-V2", &encoded])
            }
            Self::MigrateConsensusStakeSlashTerms(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("MigrateConsensusStakeSlashTermsV2 serialization is infallible");
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-MIGRATE-STAKE-SLASH-TERMS-V2",
                    &encoded,
                ])
            }
            Self::SlashConsensusStake(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("SlashConsensusStakeV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-SLASH-STAKE-V1", &encoded])
            }
            Self::ProposeStakeStateResourcePolicy(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("ProposeStakeStateResourcePolicyV1 serialization is infallible");
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-PROPOSE-STAKE-RESOURCE-POLICY-V1",
                    &encoded,
                ])
            }
            Self::ActivateStakeStateResourcePolicy(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("ActivateStakeStateResourcePolicyV1 serialization is infallible");
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-ACTIVATE-STAKE-RESOURCE-POLICY-V1",
                    &encoded,
                ])
            }
            Self::LockConsensusStakeV3(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("LockConsensusStakeRequestV3 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-LOCK-STAKE-V3", &encoded])
            }
            Self::MigrateConsensusStakeResource(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("MigrateConsensusStakeResourceRequestV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-MIGRATE-STAKE-RESOURCE-V1", &encoded])
            }
            Self::MigrateConsensusCandidateResource(request) => {
                let encoded = serde_json::to_vec(request).expect(
                    "MigrateConsensusCandidateResourceRequestV1 serialization is infallible",
                );
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-MIGRATE-CANDIDATE-RESOURCE-V1",
                    &encoded,
                ])
            }
            Self::DeriveNextStakeEpochV2(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("DeriveNextStakeEpochRequestV2 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-DERIVE-STAKE-EPOCH-V2", &encoded])
            }
            Self::RenewStakeStateResourceBond(request) => {
                let encoded = serde_json::to_vec(request)
                    .expect("RenewStakeStateResourceBondRequestV1 serialization is infallible");
                hash_parts(&[
                    b"RLD-CONSENSUS-COMMAND-RENEW-STAKE-RESOURCE-BOND-V1",
                    &encoded,
                ])
            }
            Self::CommitAdmissionCheckpoint(proof) => {
                let encoded = proof
                    .canonical_bytes()
                    .unwrap_or_else(|_| serde_json::to_vec(proof).unwrap_or_default());
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-ADMISSION-CHECKPOINT-V1", &encoded])
            }
            Self::ScheduleUpgrade(schedule) => self
                .wire_v1_command_hash(&schedule.network_domain)
                // This infallible legacy accessor must not panic on malformed
                // input. Wire encoding/signature validation still rejects it.
                .unwrap_or_else(|_| hash_bytes(b"RLD-INVALID-UPGRADE-SCHEDULE-V1")),
            Self::ActivateUpgrade(activation) => self
                .wire_v1_command_hash(&activation.network_domain)
                .unwrap_or_else(|_| hash_bytes(b"RLD-INVALID-UPGRADE-ACTIVATION-V1")),
            Self::NetworkHeartbeat(heartbeat) => {
                let encoded = serde_json::to_vec(heartbeat)
                    .expect("NetworkHeartbeatV1 serialization is infallible");
                hash_parts(&[b"RLD-CONSENSUS-COMMAND-NETWORK-HEARTBEAT-V1", &encoded])
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "result", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusOutcome {
    LocalPayment(PaymentRecord),
    ExportPayment(Box<TransitCapsule>),
    ImportCapsule(DestinationImportReceipt),
    FinalizeExport(PaymentRecord),
    ValueRiskPolicy(ValueRiskPolicy),
    Production(serde_json::Value),
    StakeAuthority(LedgerStakeAuthorityStateV1),
    DerivedStakeEpoch(LedgerDerivedStakeEpochV1),
    ConsensusStake(ConsensusStakePosition),
    StakeCandidate(ValidatorCandidateRecord),
    StakeCandidateResourceRegistration(Box<RegisterConsensusValidatorOutcomeV2>),
    ConsensusStakeResourceLock(Box<LockConsensusStakeOutcomeV3>),
    ConsensusStakeResourceMigration(Box<MigrateConsensusStakeResourceOutcomeV1>),
    ConsensusCandidateResourceMigration(Box<MigrateConsensusCandidateResourceOutcomeV1>),
    DerivedStakeEpochResource(Box<DeriveNextStakeEpochOutcomeV2>),
    StakeStateResourceBondRenewal(Box<RenewStakeStateResourceBondOutcomeV1>),
    ConsensusStakeUnbond(ConsensusStakeUnbondRecordV1),
    ConsensusStakeSlash(Box<ConsensusStakeSlashRecordV1>),
    StakeStateResourcePolicyProposal(Box<ProposeStakeStateResourcePolicyV1>),
    StakeStateResourcePolicy(StakeStateResourcePolicyV1),
    AdmissionCheckpoint(AdmissionHash32),
    NetworkHeartbeat(NetworkHeartbeatV1),
    UpgradeScheduled(crate::genesis::upgrade_pending::PendingUpgradeV1),
    UpgradeActivated(crate::genesis::M0ActiveProtocolStateV1),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusProposal {
    pub proposal_id: String,
    pub zone_id: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    pub parent_height: u64,
    pub parent_state_root: String,
    pub round: u64,
    pub proposer_public_key: String,
    pub command: ConsensusCommand,
    pub command_hash: String,
    pub expected_height: u64,
    pub expected_state_root: String,
    pub signature: String,
}

impl ConsensusProposal {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-CONSENSUS-PROPOSAL-V2".to_vec();
        put_string(&mut bytes, &self.proposal_id);
        put_string(&mut bytes, &self.zone_id);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.parent_height.to_be_bytes());
        put_string(&mut bytes, &self.parent_state_root);
        bytes.extend_from_slice(&self.round.to_be_bytes());
        put_string(&mut bytes, &self.proposer_public_key);
        put_string(&mut bytes, &self.command_hash);
        bytes.extend_from_slice(&self.expected_height.to_be_bytes());
        put_string(&mut bytes, &self.expected_state_root);
        bytes
    }

    pub fn proposal_hash(&self) -> String {
        hash_parts(&[&self.signing_bytes(), self.signature.as_bytes()])
    }

    pub fn wire_v1_canonical_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        encode_wire_json(
            WireSchema::ConsensusProposal,
            serde_json::json!({
                "network_domain": network_domain,
                "proposal_id": self.proposal_id,
                "zone_id": self.zone_id,
                "currency_genesis_root": self.currency_genesis_root,
                "protocol_era": self.protocol_era.to_string(),
                "crypto_era": self.crypto_era.to_string(),
                "parent_height": u128::from(self.parent_height).to_string(),
                "parent_state_root": self.parent_state_root,
                "round": self.round.to_string(),
                "proposer_public_key": self.proposer_public_key,
                "command_hash": self.command_hash,
                "expected_height": u128::from(self.expected_height).to_string(),
                "expected_state_root": self.expected_state_root,
            }),
        )
    }

    pub fn wire_v1_signing_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        let wire = self.wire_v1_canonical_bytes(network_domain)?;
        Ok(preimage(WireSchema::ConsensusProposal, &wire))
    }

    pub fn wire_v1_proposal_hash(&self, network_domain: &str) -> Result<String, WireError> {
        let wire = self.wire_v1_canonical_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::ConsensusProposal, &wire))
    }

    pub fn verify_wire_v1(&self, network_domain: &str) -> Result<(), WireError> {
        if self.round != 0 {
            return Err(WireError::new(
                "unsupported_consensus_round",
                "consensus is fail-closed above round zero until authenticated view change is implemented",
            ));
        }
        if self.command_hash != self.command.wire_v1_command_hash(network_domain)? {
            return Err(WireError::new(
                "command_commitment_mismatch",
                "consensus command commitment mismatch",
            ));
        }
        let next_height = self.parent_height.checked_add(1).ok_or_else(|| {
            WireError::new(
                "height_overflow",
                "consensus proposal parent height overflows u64 runtime state",
            )
        })?;
        if self.expected_height != next_height {
            return Err(WireError::new(
                "height_sequence_mismatch",
                "consensus proposal must advance exactly one height",
            ));
        }
        let signing_bytes = self.wire_v1_signing_bytes(network_domain)?;
        verify_bytes(&self.proposer_public_key, &signing_bytes, &self.signature)
            .map_err(|message| WireError::new("invalid_signature", message))
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.round != 0 {
            return Err(
                "consensus is fail-closed above round zero until authenticated view change is implemented"
                    .into(),
            );
        }
        if self.proposal_id.trim().is_empty()
            || self.zone_id.trim().is_empty()
            || self.parent_state_root.trim().is_empty()
            || self.expected_state_root.trim().is_empty()
        {
            return Err("consensus proposal identifiers and state roots are required".into());
        }
        if self.command_hash != self.command.command_hash() {
            return Err("consensus command commitment mismatch".into());
        }
        let next_height = self
            .parent_height
            .checked_add(1)
            .ok_or_else(|| "consensus proposal parent height overflow".to_string())?;
        if self.expected_height != next_height {
            return Err("consensus proposal must advance exactly one height".into());
        }
        verify_bytes(
            &self.proposer_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVote {
    pub proposal_id: String,
    pub proposal_hash: String,
    pub zone_id: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    pub parent_height: u64,
    pub parent_state_root: String,
    pub round: u64,
    pub expected_state_root: String,
    pub voter_public_key: String,
    pub signature: String,
}

impl ConsensusVote {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-CONSENSUS-VOTE-V2".to_vec();
        put_string(&mut bytes, &self.proposal_id);
        put_string(&mut bytes, &self.proposal_hash);
        put_string(&mut bytes, &self.zone_id);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.parent_height.to_be_bytes());
        put_string(&mut bytes, &self.parent_state_root);
        bytes.extend_from_slice(&self.round.to_be_bytes());
        put_string(&mut bytes, &self.expected_state_root);
        put_string(&mut bytes, &self.voter_public_key);
        bytes
    }

    pub fn wire_v1_canonical_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        encode_wire_json(
            WireSchema::ConsensusVote,
            serde_json::json!({
                "network_domain": network_domain,
                "proposal_id": self.proposal_id,
                "proposal_hash": self.proposal_hash,
                "zone_id": self.zone_id,
                "currency_genesis_root": self.currency_genesis_root,
                "protocol_era": self.protocol_era.to_string(),
                "crypto_era": self.crypto_era.to_string(),
                "parent_height": u128::from(self.parent_height).to_string(),
                "parent_state_root": self.parent_state_root,
                "round": self.round.to_string(),
                "expected_state_root": self.expected_state_root,
                "voter_public_key": self.voter_public_key,
            }),
        )
    }

    pub fn wire_v1_signing_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        let wire = self.wire_v1_canonical_bytes(network_domain)?;
        Ok(preimage(WireSchema::ConsensusVote, &wire))
    }

    pub fn wire_v1_vote_hash(&self, network_domain: &str) -> Result<String, WireError> {
        let wire = self.wire_v1_canonical_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::ConsensusVote, &wire))
    }

    pub fn verify_for_wire_v1(
        &self,
        proposal: &ConsensusProposal,
        network_domain: &str,
    ) -> Result<(), WireError> {
        if self.round != 0 || proposal.round != 0 {
            return Err(WireError::new(
                "unsupported_consensus_round",
                "consensus votes are fail-closed above round zero until authenticated view change is implemented",
            ));
        }
        let proposal_hash = proposal.wire_v1_proposal_hash(network_domain)?;
        if self.proposal_id != proposal.proposal_id
            || self.proposal_hash != proposal_hash
            || self.zone_id != proposal.zone_id
            || self.currency_genesis_root != proposal.currency_genesis_root
            || self.protocol_era != proposal.protocol_era
            || self.crypto_era != proposal.crypto_era
            || self.parent_height != proposal.parent_height
            || self.parent_state_root != proposal.parent_state_root
            || self.round != proposal.round
            || self.expected_state_root != proposal.expected_state_root
        {
            return Err(WireError::new(
                "vote_proposal_mismatch",
                "consensus vote does not bind to the proposal",
            ));
        }
        let signing_bytes = self.wire_v1_signing_bytes(network_domain)?;
        verify_bytes(&self.voter_public_key, &signing_bytes, &self.signature)
            .map_err(|message| WireError::new("invalid_signature", message))
    }

    pub fn verify_for(&self, proposal: &ConsensusProposal) -> Result<(), String> {
        if self.round != 0 || proposal.round != 0 {
            return Err(
                "consensus votes are fail-closed above round zero until authenticated view change is implemented"
                    .into(),
            );
        }
        if self.proposal_id != proposal.proposal_id
            || self.proposal_hash != proposal.proposal_hash()
            || self.zone_id != proposal.zone_id
            || self.currency_genesis_root != proposal.currency_genesis_root
            || self.protocol_era != proposal.protocol_era
            || self.crypto_era != proposal.crypto_era
            || self.parent_height != proposal.parent_height
            || self.parent_state_root != proposal.parent_state_root
            || self.round != proposal.round
            || self.expected_state_root != proposal.expected_state_root
        {
            return Err("consensus vote does not bind to the proposal".into());
        }
        verify_bytes(
            &self.voter_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusCommit {
    pub proposal: ConsensusProposal,
    pub votes: Vec<ConsensusVote>,
}

impl ConsensusCommit {
    pub fn commit_hash(&self) -> String {
        hash_parts(&[
            b"RLD-CONSENSUS-COMMIT-V1",
            self.proposal.proposal_hash().as_bytes(),
            self.proposal.expected_state_root.as_bytes(),
        ])
    }

    pub fn wire_v1_canonical_bytes(&self, network_domain: &str) -> Result<Vec<u8>, WireError> {
        let mut vote_hashes = self
            .votes
            .iter()
            .map(|vote| vote.wire_v1_vote_hash(network_domain))
            .collect::<Result<Vec<_>, _>>()?;
        vote_hashes.sort();
        encode_wire_json(
            WireSchema::ConsensusCommit,
            serde_json::json!({
                "network_domain": network_domain,
                "zone_id": self.proposal.zone_id,
                "currency_genesis_root": self.proposal.currency_genesis_root,
                "protocol_era": self.proposal.protocol_era.to_string(),
                "crypto_era": self.proposal.crypto_era.to_string(),
                "proposal_hash": self.proposal.wire_v1_proposal_hash(network_domain)?,
                "expected_height": u128::from(self.proposal.expected_height).to_string(),
                "expected_state_root": self.proposal.expected_state_root,
                "vote_hashes": vote_hashes,
            }),
        )
    }

    pub fn wire_v1_commit_hash(&self, network_domain: &str) -> Result<String, WireError> {
        let wire = self.wire_v1_canonical_bytes(network_domain)?;
        Ok(digest_hex(WireSchema::ConsensusCommit, &wire))
    }

    pub fn verify_wire_v1(
        &self,
        validator_keys: &[String],
        network_domain: &str,
    ) -> Result<(), WireError> {
        self.proposal.verify_wire_v1(network_domain)?;
        let expected_leader =
            deterministic_round_zero_leader(validator_keys, self.proposal.parent_height)
                .map_err(|message| WireError::new("invalid_validator_set", message))?;
        if self.proposal.proposer_public_key != expected_leader {
            return Err(WireError::new(
                "unauthorized_proposer",
                "consensus proposer is not the deterministic round-zero leader",
            ));
        }
        let required = required_quorum(validator_keys.len())
            .map_err(|message| WireError::new("invalid_validator_set", message))?;
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for vote in &self.votes {
            if validator_keys.contains(&vote.voter_public_key)
                && seen.insert(vote.voter_public_key.clone())
                && vote
                    .verify_for_wire_v1(&self.proposal, network_domain)
                    .is_ok()
            {
                valid += 1;
            }
        }
        if valid < required {
            return Err(WireError::new(
                "quorum_not_met",
                format!("consensus quorum not met: {valid} valid votes, {required} required"),
            ));
        }
        self.wire_v1_canonical_bytes(network_domain)?;
        Ok(())
    }

    pub fn verify(&self, validator_keys: &[String]) -> Result<(), String> {
        self.proposal.verify()?;
        let expected_leader =
            deterministic_round_zero_leader(validator_keys, self.proposal.parent_height)?;
        if self.proposal.proposer_public_key != expected_leader {
            return Err("consensus proposer is not the deterministic round-zero leader".into());
        }
        let required = required_quorum(validator_keys.len())?;
        let mut seen = std::collections::BTreeSet::new();
        let mut valid = 0usize;
        for vote in &self.votes {
            if validator_keys.contains(&vote.voter_public_key)
                && seen.insert(vote.voter_public_key.clone())
                && vote.verify_for(&self.proposal).is_ok()
            {
                valid += 1;
            }
        }
        if valid < required {
            return Err(format!(
                "consensus quorum not met: {valid} valid votes, {required} required"
            ));
        }
        Ok(())
    }
}

impl UniversalPaymentIntent {
    /// Stable, language-neutral signing message used by Rust, CLI and WebCrypto.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-PAYMENT-V2".to_vec();
        put_string(&mut bytes, &self.payment_id);
        put_string(&mut bytes, &self.source_zone);
        put_string(&mut bytes, &self.destination_zone);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.pricing_epoch.to_be_bytes());
        put_string(&mut bytes, &self.sender_public_key);
        put_string(&mut bytes, &self.recipient);
        put_string(&mut bytes, &self.coin_id);
        bytes.extend_from_slice(&self.amount.0.to_be_bytes());
        bytes.extend_from_slice(&self.max_fee.0.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        if let Some(request_id) = &self.payment_request_id {
            put_string(&mut bytes, "RLD-PAYMENT-REQUEST-BINDING-V1");
            put_string(&mut bytes, request_id);
            put_string(
                &mut bytes,
                self.payment_request
                    .as_ref()
                    .map(PaymentRequest::commitment_hash)
                    .as_deref()
                    .unwrap_or_default(),
            );
        }
        if let Some(quote_id) = &self.route_quote_id {
            put_string(&mut bytes, "RLD-ROUTE-QUOTE-BINDING-V1");
            put_string(&mut bytes, quote_id);
        }
        bytes
    }

    pub fn verify(&self) -> Result<(), String> {
        verify_bytes(
            &self.sender_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedActionAuthorization {
    pub authorization_id: String,
    pub zone_id: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    pub signer_public_key: String,
    pub action: String,
    pub payload_hash: String,
    pub nonce: u64,
    pub signature: String,
}

impl SignedActionAuthorization {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-AUTHORIZATION-V2".to_vec();
        put_string(&mut bytes, &self.authorization_id);
        put_string(&mut bytes, &self.zone_id);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        put_string(&mut bytes, &self.signer_public_key);
        put_string(&mut bytes, &self.action);
        put_string(&mut bytes, &self.payload_hash);
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes
    }

    pub fn verify_scope(
        &self,
        expected_zone: &str,
        expected_currency_genesis_root: &str,
        expected_protocol_era: u64,
        expected_crypto_era: u64,
        expected_action: &str,
        expected_payload_hash: &str,
    ) -> Result<(), String> {
        if self.zone_id != expected_zone
            || self.currency_genesis_root != expected_currency_genesis_root
            || self.protocol_era != expected_protocol_era
            || self.crypto_era != expected_crypto_era
            || self.action != expected_action
            || self.payload_hash != expected_payload_hash
        {
            return Err("authorization scope mismatch".into());
        }
        verify_bytes(
            &self.signer_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }

    pub fn signer_address(&self) -> String {
        format!("rld:{}:{}", self.zone_id, self.signer_public_key)
    }
}

pub fn action_payload_hash(action: &str, fields: &[&[u8]]) -> String {
    let mut parts = Vec::with_capacity(fields.len() + 2);
    parts.push(b"RLD-ACTION-PAYLOAD-V1".as_slice());
    parts.push(action.as_bytes());
    parts.extend_from_slice(fields);
    hash_parts(&parts)
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn encode_wire_json(schema: WireSchema, value: serde_json::Value) -> Result<Vec<u8>, WireError> {
    let source = value
        .as_object()
        .ok_or_else(|| WireError::new("wrong_type", "wire source must be an object"))?;
    encode_source(schema, source)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PaymentStatus {
    Created,
    SourceReserved,
    SourceFinal,
    InTransit,
    LocalSpendable,
    UniversallySettled,
    Returning,
    Returned,
    RouteExhausted,
    Quarantined,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteQuoteStatus {
    Open,
    Locked,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteQuote {
    pub quote_id: String,
    pub provider: String,
    pub source_zone: String,
    pub destination_zone: String,
    pub route: Vec<String>,
    pub transport: TransportClass,
    pub base_fee: Amount,
    pub authorized_reroute_budget: Amount,
    #[serde(default)]
    pub consumed_reroute_fee: Amount,
    pub expires_at_height: u64,
    pub status: RouteQuoteStatus,
    pub locked_payment_id: Option<String>,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateRouteQuoteRequest {
    pub provider: String,
    pub destination_zone: String,
    pub route: Vec<String>,
    pub transport: TransportClass,
    pub base_fee: Amount,
    pub authorized_reroute_budget: Amount,
    pub expires_at_height: u64,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RerouteRouteQuoteRequest {
    pub failed_hop: String,
    pub replacement_route: Vec<String>,
    pub incremental_fee: Amount,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRecord {
    pub intent: UniversalPaymentIntent,
    pub status: PaymentStatus,
    pub output_coin_ids: Vec<String>,
    pub transit_id: Option<String>,
    pub updated_height: u64,
    #[serde(default)]
    pub charged_fee: Amount,
    #[serde(default)]
    pub fee_resources: ResourceVector,
    #[serde(default)]
    pub pricing_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedAttestation {
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub subject_hash: String,
    pub threshold: u16,
    pub attestations: Vec<SignedAttestation>,
    pub testnet_simulated: bool,
}

impl QuorumCertificate {
    pub fn verify(&self, allowed_keys: &[String]) -> Result<(), String> {
        if self.testnet_simulated {
            return Err("simulated quorum certificates are not valid for trusted import".into());
        }
        let required = required_quorum(allowed_keys.len())?;
        let declared = self.threshold as usize;
        if declared < required {
            return Err(format!(
                "unsafe quorum threshold: {declared} declared, at least {required} required"
            ));
        }
        if declared > allowed_keys.len() {
            return Err("quorum threshold exceeds the configured member set".into());
        }
        let mut valid = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for attestation in &self.attestations {
            if allowed_keys.contains(&attestation.public_key)
                && seen.insert(attestation.public_key.clone())
                && verify_bytes(
                    &attestation.public_key,
                    self.subject_hash.as_bytes(),
                    &attestation.signature,
                )
                .is_ok()
            {
                valid += 1;
            }
        }
        if valid < declared {
            return Err(format!(
                "quorum not met: {valid} valid signatures, {} required",
                self.threshold
            ));
        }
        Ok(())
    }
}

pub fn required_quorum(member_count: usize) -> Result<usize, String> {
    if member_count == 0 {
        return Err("quorum member set is empty".into());
    }
    // This is exactly floor(2*n/3)+1, expressed without the overflowing 2*n
    // intermediate. It remains correct for every representable `usize`.
    Ok(member_count - (member_count - 1) / 3)
}

/// Selects the only proposer accepted while consensus supports round zero.
///
/// The persisted validator set is treated as a set rather than as CLI order:
/// every node sorts the verified public keys and rotates by parent height.
/// Duplicate keys are rejected because they would make both leader selection
/// and quorum accounting ambiguous.
pub fn deterministic_round_zero_leader(
    validator_keys: &[String],
    parent_height: u64,
) -> Result<String, String> {
    deterministic_round_leader(validator_keys, parent_height, 0)
}

/// Selects the unique proposer for a consensus height and authenticated round.
///
/// The calculation avoids overflowing `parent_height + round`. A nonzero round
/// is not authorized by this function alone; callers must first verify the
/// timeout certificate for the immediately preceding round.
pub fn deterministic_round_leader(
    validator_keys: &[String],
    parent_height: u64,
    round: u64,
) -> Result<String, String> {
    if validator_keys.is_empty() {
        return Err("consensus validator set is empty".into());
    }
    let mut canonical = validator_keys.to_vec();
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("consensus validator set contains duplicate public keys".into());
    }
    let count = u64::try_from(canonical.len())
        .map_err(|_| "consensus validator count does not fit u64".to_owned())?;
    let index_u64 = u64::try_from(
        (u128::from(parent_height % count) + u128::from(round % count)) % u128::from(count),
    )
    .map_err(|_| "consensus leader index does not fit u64".to_owned())?;
    let index = usize::try_from(index_u64)
        .map_err(|_| "consensus leader index does not fit usize".to_owned())?;
    Ok(canonical[index].clone())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoSuiteDescriptor {
    pub suite_id: String,
    pub signature_algorithm: String,
    pub hash_algorithm: String,
    pub encoding: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EraContinuityCertificate {
    pub zone_id: String,
    pub previous_protocol_era: u64,
    pub new_protocol_era: u64,
    pub previous_crypto_era: u64,
    pub new_crypto_era: u64,
    pub previous_certificate_hash: String,
    pub activation_checkpoint: String,
    pub irreversible_height: u64,
    pub new_suite: CryptoSuiteDescriptor,
    pub previous_validator_keys: Vec<String>,
    pub previous_notary_keys: Vec<String>,
    pub new_validator_keys: Vec<String>,
    pub new_notary_keys: Vec<String>,
    pub old_crypto_qc: QuorumCertificate,
    pub new_crypto_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
    pub certificate_hash: String,
}

impl EraContinuityCertificate {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            self.zone_id.as_bytes(),
            &self.previous_protocol_era.to_be_bytes(),
            &self.new_protocol_era.to_be_bytes(),
            &self.previous_crypto_era.to_be_bytes(),
            &self.new_crypto_era.to_be_bytes(),
            self.previous_certificate_hash.as_bytes(),
            self.activation_checkpoint.as_bytes(),
            &self.irreversible_height.to_be_bytes(),
            self.new_suite.suite_id.as_bytes(),
            self.new_suite.signature_algorithm.as_bytes(),
            self.new_suite.hash_algorithm.as_bytes(),
            self.new_suite.encoding.as_bytes(),
            self.previous_validator_keys.join("|").as_bytes(),
            self.previous_notary_keys.join("|").as_bytes(),
            self.new_validator_keys.join("|").as_bytes(),
            self.new_notary_keys.join("|").as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationalProof {
    pub checkpoint_hash: String,
    pub object_hash: String,
    #[serde(default)]
    pub continuity_accumulator: String,
    #[serde(default)]
    pub lineage_merkle_path: Vec<String>,
    pub transition_hashes: Vec<String>,
    pub protocol_era: u64,
    pub crypto_era: u64,
    #[serde(default)]
    pub era_certificate_hash: String,
    #[serde(default)]
    pub supply_certificate_hash: String,
    #[serde(default)]
    pub transit_nullifier_commitment: String,
}

impl OperationalProof {
    pub fn append_transition(&mut self, transition_hash: String) -> Result<(), String> {
        if transition_hash.is_empty() {
            return Err("transition hash is required".into());
        }
        if self.transition_hashes.len() == MAX_RECENT_TRANSITIONS {
            let mut bytes = self.continuity_accumulator.as_bytes().to_vec();
            for item in &self.transition_hashes {
                bytes.extend_from_slice(item.as_bytes());
            }
            self.continuity_accumulator = hash_bytes(&bytes);
            self.transition_hashes.clear();
        }
        self.transition_hashes.push(transition_hash);
        self.validate_bounds()
    }

    pub fn commitment_hash(&self) -> String {
        hash_parts(&[
            self.checkpoint_hash.as_bytes(),
            self.object_hash.as_bytes(),
            self.continuity_accumulator.as_bytes(),
            self.lineage_merkle_path.join("|").as_bytes(),
            self.transition_hashes.join("|").as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
            self.era_certificate_hash.as_bytes(),
            self.supply_certificate_hash.as_bytes(),
            self.transit_nullifier_commitment.as_bytes(),
        ])
    }

    pub fn encoded_len(&self) -> Result<usize, String> {
        serde_json::to_vec(self)
            .map(|bytes| bytes.len())
            .map_err(|error| error.to_string())
    }

    pub fn validate_bounds(&self) -> Result<(), String> {
        if self.checkpoint_hash.is_empty()
            || self.object_hash.is_empty()
            || self.continuity_accumulator.is_empty()
            || self.era_certificate_hash.is_empty()
            || self.supply_certificate_hash.is_empty()
            || self.transit_nullifier_commitment.is_empty()
        {
            return Err("operational proof is incomplete".into());
        }
        if self.transition_hashes.len() > MAX_RECENT_TRANSITIONS {
            return Err("too many recent transitions".into());
        }
        if self.lineage_merkle_path.len() > MAX_LINEAGE_MERKLE_PATH {
            return Err("lineage Merkle path exceeds protocol bound".into());
        }
        if self.encoded_len()? > MAX_OPERATIONAL_PROOF_BYTES {
            return Err("operational proof exceeds 512 KiB".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitCapsule {
    pub transit_id: String,
    pub payment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request: Option<PaymentRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_quote_id: Option<String>,
    pub source_zone: String,
    pub destination_zone: String,
    pub source_descriptor: ZoneDescriptor,
    pub recipient: String,
    pub amount: Amount,
    pub lineage_root: String,
    pub source_object_id: String,
    pub source_object_version: u64,
    pub source_object: CoinObject,
    pub source_supply: SupplyConservationCertificate,
    pub origin_genesis_root: String,
    pub source_checkpoint: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
    pub operational_proof: OperationalProof,
    pub era_certificate: Option<EraContinuityCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_endorsement: Option<GatewayEndorsement>,
    pub transport: TransportClass,
}

impl TransitCapsule {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            self.transit_id.as_bytes(),
            self.payment_id.as_bytes(),
            self.payment_request_id
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            self.payment_request
                .as_ref()
                .map(PaymentRequest::commitment_hash)
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            self.route_quote_id
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            self.source_zone.as_bytes(),
            self.destination_zone.as_bytes(),
            self.recipient.as_bytes(),
            &self.amount.0.to_be_bytes(),
            self.lineage_root.as_bytes(),
            self.source_object_id.as_bytes(),
            &self.source_object_version.to_be_bytes(),
            self.operational_proof.commitment_hash().as_bytes(),
            self.source_supply.merkle_sum_root.as_bytes(),
            self.origin_genesis_root.as_bytes(),
            self.source_checkpoint.as_bytes(),
        ])
    }

    pub fn source_spend_nullifier(&self) -> String {
        hash_parts(&[
            b"RLD-SOURCE-SPEND-V1",
            self.source_zone.as_bytes(),
            self.source_object_id.as_bytes(),
            &self.source_object_version.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GatewayBondStatus {
    Active,
    Slashed,
    Released,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayBond {
    pub bond_id: String,
    pub source_zone: String,
    pub owner: String,
    pub gateway_public_key: String,
    pub amount: Amount,
    pub escrow_coin_id: String,
    pub status: GatewayBondStatus,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateGatewayBondRequest {
    pub source_zone: String,
    pub owner: String,
    pub gateway_public_key: String,
    pub coin_id: String,
    pub amount: Amount,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayEndorsement {
    pub bond_id: String,
    pub source_zone: String,
    pub gateway_public_key: String,
    pub capsule_subject_hash: String,
    pub signature: String,
}

impl GatewayEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-GATEWAY-ENDORSEMENT-V1".to_vec();
        put_string(&mut bytes, &self.bond_id);
        put_string(&mut bytes, &self.source_zone);
        put_string(&mut bytes, &self.gateway_public_key);
        put_string(&mut bytes, &self.capsule_subject_hash);
        bytes
    }

    pub fn verify(&self, capsule: &TransitCapsule) -> Result<(), String> {
        if self.source_zone != capsule.source_zone
            || self.capsule_subject_hash != capsule.subject_hash()
        {
            return Err("gateway endorsement does not bind to this transit capsule".into());
        }
        verify_bytes(
            &self.gateway_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DestinationRejectionReason {
    RecipientDeclined,
    PolicyRejected,
    ProtocolUnsupported,
    RouteUnavailable,
    InvalidCommercialRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationRejectionProof {
    pub rejection_id: String,
    pub transit_id: String,
    pub payment_id: String,
    pub source_zone: String,
    pub destination_zone: String,
    pub source_object_id: String,
    pub source_object_version: u64,
    pub recipient: String,
    pub amount: Amount,
    pub reason: DestinationRejectionReason,
    pub destination_descriptor: ZoneDescriptor,
    pub destination_height: u64,
    pub destination_checkpoint: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl DestinationRejectionProof {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-DESTINATION-REJECTION-V1",
            self.rejection_id.as_bytes(),
            self.transit_id.as_bytes(),
            self.payment_id.as_bytes(),
            self.source_zone.as_bytes(),
            self.destination_zone.as_bytes(),
            self.source_object_id.as_bytes(),
            &self.source_object_version.to_be_bytes(),
            self.recipient.as_bytes(),
            &self.amount.0.to_be_bytes(),
            rejection_reason_code(&self.reason),
            self.destination_descriptor.genesis_root.as_bytes(),
            &self.destination_descriptor.protocol_era.to_be_bytes(),
            &self.destination_descriptor.crypto_era.to_be_bytes(),
            &self.destination_height.to_be_bytes(),
            self.destination_checkpoint.as_bytes(),
        ])
    }
}

fn rejection_reason_code(reason: &DestinationRejectionReason) -> &'static [u8] {
    match reason {
        DestinationRejectionReason::RecipientDeclined => b"RECIPIENT_DECLINED",
        DestinationRejectionReason::PolicyRejected => b"POLICY_REJECTED",
        DestinationRejectionReason::ProtocolUnsupported => b"PROTOCOL_UNSUPPORTED",
        DestinationRejectionReason::RouteUnavailable => b"ROUTE_UNAVAILABLE",
        DestinationRejectionReason::InvalidCommercialRequest => b"INVALID_COMMERCIAL_REQUEST",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationImportReceipt {
    pub transit_id: String,
    pub payment_id: String,
    pub destination_zone: String,
    pub destination_coin_id: String,
    pub recipient: String,
    pub amount: Amount,
    pub destination_height: u64,
    pub checkpoint_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientReceipt {
    pub receipt_id: String,
    pub payment_id: String,
    pub settlement_reference: String,
    pub destination_zone: String,
    #[serde(default)]
    pub currency_genesis_root: String,
    #[serde(default)]
    pub protocol_era: u64,
    #[serde(default)]
    pub crypto_era: u64,
    pub recipient: String,
    pub recipient_public_key: String,
    pub amount: Amount,
    pub observed_destination_height: u64,
    pub nonce: u64,
    pub signature: String,
}

impl RecipientReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"RLD-RECIPIENT-RECEIPT-V2".to_vec();
        put_string(&mut bytes, &self.receipt_id);
        put_string(&mut bytes, &self.payment_id);
        put_string(&mut bytes, &self.settlement_reference);
        put_string(&mut bytes, &self.destination_zone);
        put_string(&mut bytes, &self.currency_genesis_root);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        put_string(&mut bytes, &self.recipient);
        put_string(&mut bytes, &self.recipient_public_key);
        bytes.extend_from_slice(&self.amount.0.to_be_bytes());
        bytes.extend_from_slice(&self.observed_destination_height.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        bytes
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.receipt_id.trim().is_empty()
            || self.payment_id.trim().is_empty()
            || self.settlement_reference.trim().is_empty()
            || self.amount.is_zero()
        {
            return Err("recipient receipt is incomplete".into());
        }
        let expected_recipient = format!(
            "rld:{}:{}",
            self.destination_zone, self.recipient_public_key
        );
        if self.recipient != expected_recipient {
            return Err("recipient receipt signer does not match recipient".into());
        }
        verify_bytes(
            &self.recipient_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestinationSpendabilityCertificate {
    pub payment_id: String,
    pub destination_zone: String,
    pub recipient: String,
    pub local_coin_id: String,
    pub liquidity_provider: String,
    pub amount: Amount,
    pub settlement_claim_transit_id: String,
    pub destination_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendabilityCertificateRequest {
    pub payment_id: String,
    pub provider_coin_id: String,
    pub liquidity_provider: String,
    pub recipient: String,
    pub amount: Amount,
    pub settlement_claim_transit_id: String,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiquidityOfferStatus {
    Open,
    Depleted,
    Expired,
    Cancelled,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityOffer {
    pub offer_id: String,
    pub provider: String,
    pub destination_zone: String,
    pub reserved_coin_id: Option<String>,
    pub available: Amount,
    pub minimum: Amount,
    pub maximum: Amount,
    pub expires_at_height: u64,
    pub status: LiquidityOfferStatus,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateLiquidityOfferRequest {
    pub provider: String,
    pub coin_id: String,
    pub amount: Amount,
    pub minimum: Amount,
    pub maximum: Amount,
    pub expires_at_height: u64,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TakeLiquidityOfferRequest {
    pub offer_id: String,
    pub settlement_claim: TransitCapsule,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TravelerCarryCapsule {
    pub capsule_id: String,
    pub owner: String,
    pub issued_height: u64,
    pub transit: TransitCapsule,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SupplyBuckets {
    pub reserve: Amount,
    #[serde(default)]
    pub fee_pools: Amount,
    pub spendable: Amount,
    pub reserved: Amount,
    pub in_transit: Amount,
    pub returning: Amount,
    pub quarantined: Amount,
    pub imported_total: Amount,
    pub finalized_export_total: Amount,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolReservePools {
    pub startup_services: Amount,
    pub continuity_services: Amount,
    pub demand_matching: Amount,
}

impl ProtocolReservePools {
    pub fn total(&self) -> Result<Amount, String> {
        self.startup_services
            .checked_add(self.continuity_services)
            .and_then(|value| value.checked_add(self.demand_matching))
            .map_err(|error| error.to_string())
    }
}

impl SupplyBuckets {
    pub fn active_total(&self) -> Result<Amount, String> {
        [
            self.reserve,
            self.fee_pools,
            self.spendable,
            self.reserved,
            self.in_transit,
            self.returning,
            self.quarantined,
        ]
        .into_iter()
        .try_fold(Amount::ZERO, |sum, value| {
            sum.checked_add(value).map_err(|error| error.to_string())
        })
    }

    pub fn conservation_position(&self) -> Result<Amount, String> {
        self.active_total()?
            .checked_add(self.finalized_export_total)
            .and_then(|value| value.checked_sub(self.imported_total))
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyConservationCertificate {
    pub zone_id: String,
    pub height: u64,
    pub merkle_sum_root: String,
    pub buckets: SupplyBuckets,
    #[serde(default)]
    pub reserve_pools: ProtocolReservePools,
    pub conservation_position: Amount,
    pub anchor_supply: Amount,
    pub valid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContinuityCheckpoint {
    pub zone_id: String,
    pub height: u64,
    pub state_root: String,
    pub supply: SupplyConservationCertificate,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub previous_checkpoint: Option<String>,
    pub checkpoint_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditProofBundle {
    pub zone_descriptor: ZoneDescriptor,
    pub currency_genesis_root: String,
    pub generated_height: u64,
    pub checkpoints: Vec<ContinuityCheckpoint>,
    pub era_certificates: Vec<EraContinuityCertificate>,
    pub coin_history: Vec<CoinObject>,
    pub payments: Vec<PaymentRecord>,
    pub transits: Vec<TransitCapsule>,
    pub import_receipts: Vec<DestinationImportReceipt>,
    pub rejection_proofs: Vec<DestinationRejectionProof>,
    pub recipient_receipts: Vec<RecipientReceipt>,
    pub liquidity_offers: Vec<LiquidityOffer>,
    pub route_quotes: Vec<RouteQuote>,
    #[serde(default)]
    pub epoch_fee_pools: Vec<EpochFeePool>,
    #[serde(default)]
    pub service_orders: Vec<ServiceOrder>,
    #[serde(default)]
    pub service_leases: Vec<ServiceLease>,
    #[serde(default)]
    pub protocol_reserve_commitments: Vec<ProtocolReserveCommitment>,
    #[serde(default)]
    pub economic_control_attestations: Vec<EconomicControlAttestation>,
    #[serde(default)]
    pub economic_price_attestations: Vec<EconomicPriceAttestation>,
    #[serde(default)]
    pub economic_release_policies: Vec<EconomicReleasePolicy>,
    #[serde(default)]
    pub protocol_service_bonds: Vec<ProtocolServiceBond>,
    #[serde(default)]
    pub protocol_reserve_releases: Vec<ProtocolReserveReleaseRecord>,
    #[serde(default)]
    pub consensus_commits: Vec<ConsensusCommit>,
    #[serde(default)]
    pub m0_network_birth: Option<M0NetworkBirthStateV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m0_network_birth_v3: Option<crate::M0NetworkBirthStateV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m0_active_protocol: Option<crate::M0ActiveProtocolStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m0_pending_upgrade: Option<crate::genesis::upgrade_pending::PendingUpgradeV1>,
    #[serde(default)]
    pub admission_state: Option<LedgerAdmissionStateV1>,
    #[serde(default)]
    pub consensus_stake_authority: Option<LedgerStakeAuthorityStateV1>,
    #[serde(default)]
    pub consensus_stake_escrows: Vec<ConsensusStakePosition>,
    #[serde(default)]
    pub consensus_stake_unbonds: Vec<ConsensusStakeUnbondRecordV1>,
    #[serde(default)]
    pub consensus_stake_slashes: Vec<ConsensusStakeSlashRecordV1>,
    #[serde(default)]
    pub derived_stake_epochs: Vec<LedgerDerivedStakeEpochV1>,
    #[serde(default)]
    pub stake_position_liability_horizons: BTreeMap<String, StakePositionLiabilityHorizonV1>,
    #[serde(default)]
    pub stake_position_liability_horizon_history:
        BTreeMap<String, Vec<StakePositionLiabilityHorizonV1>>,
    #[serde(default)]
    pub stake_liability_horizon_activation_epoch: Option<u64>,
    /// Immutable governance history and the bounded stake-resource accounting
    /// plane. R6.19 admits resource-bound candidate and position creation plus
    /// exact legacy-position migration; this is not a general lifecycle or
    /// mainnet-readiness claim.
    #[serde(default)]
    pub stake_resource_policy_proposals: Vec<ProposeStakeStateResourcePolicyV1>,
    #[serde(default)]
    pub stake_resource_policy_activations: Vec<ActivateStakeStateResourcePolicyV1>,
    #[serde(default)]
    pub pending_stake_resource_policy: Option<ProposeStakeStateResourcePolicyV1>,
    #[serde(default)]
    pub stake_resource_accounting: Option<StakeStateResourceAccountingV1>,
    #[serde(default)]
    pub authorization_nullifiers: BTreeSet<String>,
    #[serde(default)]
    pub gateway_bonds: Vec<GatewayBond>,
    pub service_receipts: Vec<ServiceReceipt>,
    pub voyage_receipts: Vec<VoyageServiceReceipt>,
    pub final_state_root: String,
    pub commitment_hash: String,
}

impl AuditProofBundle {
    fn stake_resource_signer_sets_for_era(
        &self,
        protocol_era: u64,
        crypto_era: u64,
    ) -> Option<(&[String], &[String])> {
        if protocol_era == self.zone_descriptor.protocol_era
            && crypto_era == self.zone_descriptor.crypto_era
        {
            return Some((
                self.zone_descriptor.validator_keys.as_slice(),
                self.zone_descriptor.notary_keys.as_slice(),
            ));
        }
        self.era_certificates.iter().find_map(|certificate| {
            if protocol_era == certificate.previous_protocol_era
                && crypto_era == certificate.previous_crypto_era
            {
                Some((
                    certificate.previous_validator_keys.as_slice(),
                    certificate.previous_notary_keys.as_slice(),
                ))
            } else if protocol_era == certificate.new_protocol_era
                && crypto_era == certificate.new_crypto_era
            {
                Some((
                    certificate.new_validator_keys.as_slice(),
                    certificate.new_notary_keys.as_slice(),
                ))
            } else {
                None
            }
        })
    }

    fn verify_stake_resource_dual_quorum(
        &self,
        protocol_era: u64,
        crypto_era: u64,
        subject: &str,
        validator_qc: &QuorumCertificate,
        notary_qc: &QuorumCertificate,
    ) -> Result<(), String> {
        if validator_qc.subject_hash != subject || notary_qc.subject_hash != subject {
            return Err("audit resource-policy quorum subject mismatch".into());
        }
        let (validator_keys, notary_keys) = self
            .stake_resource_signer_sets_for_era(protocol_era, crypto_era)
            .ok_or("audit resource-policy record refers to an unknown era")?;
        let simulated = validator_qc.testnet_simulated && notary_qc.testnet_simulated;
        if simulated {
            if self.zone_descriptor.testnet && validator_keys.is_empty() && notary_keys.is_empty() {
                return Ok(());
            }
            return Err(
                "audit simulated resource-policy quorum is forbidden for this signer set".into(),
            );
        }
        if validator_qc.testnet_simulated || notary_qc.testnet_simulated {
            return Err("audit resource-policy quorum modes differ".into());
        }
        validator_qc.verify(validator_keys)?;
        notary_qc.verify(notary_keys)
    }

    pub fn compute_commitment(&self) -> Result<String, String> {
        let mut payload = self.clone();
        payload.commitment_hash.clear();
        serde_json::to_vec(&payload)
            .map(|bytes| hash_bytes(&bytes))
            .map_err(|error| error.to_string())
    }

    pub fn verify_structure(&self) -> Result<(), String> {
        if self.currency_genesis_root != self.zone_descriptor.currency_genesis_root {
            return Err("audit bundle currency genesis root mismatch".into());
        }
        if let Some(pending) = &self.m0_pending_upgrade {
            let birth = self
                .m0_network_birth_v3
                .as_ref()
                .ok_or("audit pending upgrade requires V3 birth")?;
            let active = self
                .m0_active_protocol
                .as_ref()
                .ok_or("audit pending upgrade requires active state")?;
            pending.validate(
                &self.zone_descriptor,
                birth,
                active,
                u128::from(self.generated_height),
            )?;
        }
        let birth_genesis = match (
            &self.m0_network_birth,
            &self.m0_network_birth_v3,
            &self.m0_active_protocol,
        ) {
            (None, None, None) => None,
            (Some(birth), None, None) => {
                birth.validate_for_descriptor(&self.zone_descriptor)?;
                Some(&birth.admission_genesis)
            }
            (None, Some(birth), Some(active)) => {
                birth.validate_for_descriptor(&self.zone_descriptor)?;
                active.validate_for_birth(birth)?;
                Some(&birth.admission_genesis)
            }
            _ => return Err("audit mixed, missing or downgraded M0 birth/active state".into()),
        };
        match (birth_genesis, &self.admission_state) {
            (None, None) => {}
            (Some(admission_genesis), Some(admission_state)) => {
                admission_state
                    .validate_for_descriptor(&self.zone_descriptor)
                    .map_err(|error| error.to_string())?;
                if admission_genesis != &admission_state.genesis {
                    return Err("audit M0 network birth and admission trust roots differ".into());
                }
            }
            _ => {
                return Err(
                    "audit M0 network birth and admission state must be present together".into(),
                );
            }
        }
        if self.checkpoints.is_empty() {
            return Err("audit bundle has no continuity checkpoints".into());
        }
        let mut previous: Option<&ContinuityCheckpoint> = None;
        for checkpoint in &self.checkpoints {
            if checkpoint.zone_id != self.zone_descriptor.zone_id
                || !checkpoint.supply.valid
                || checkpoint.supply.zone_id != self.zone_descriptor.zone_id
            {
                return Err("audit checkpoint Zone or supply binding mismatch".into());
            }
            let position = checkpoint.supply.buckets.conservation_position()?;
            if position != checkpoint.supply.conservation_position
                || position != checkpoint.supply.anchor_supply
            {
                return Err("audit checkpoint violates supply conservation".into());
            }
            if let Some(parent) = previous {
                if checkpoint.previous_checkpoint.as_deref() != Some(&parent.checkpoint_hash)
                    || checkpoint.height < parent.height
                {
                    return Err("audit checkpoint chain is broken".into());
                }
            } else if checkpoint.previous_checkpoint.is_some() {
                return Err("audit bundle does not begin at genesis checkpoint".into());
            }
            previous = Some(checkpoint);
        }
        let latest = previous.expect("non-empty checkpoint list");
        if latest.height != self.generated_height || latest.state_root != self.final_state_root {
            return Err("audit bundle final checkpoint mismatch".into());
        }
        let resource_proposals = self
            .stake_resource_policy_proposals
            .iter()
            .map(|proposal| (proposal.proposal_id.as_str(), proposal))
            .collect::<BTreeMap<_, _>>();
        if resource_proposals.len() != self.stake_resource_policy_proposals.len() {
            return Err("audit resource-policy proposal history contains duplicate ids".into());
        }
        for proposal in &self.stake_resource_policy_proposals {
            if proposal.proposal_id.trim().is_empty()
                || proposal.network_domain != self.zone_descriptor.network_domain
                || proposal.zone_id != self.zone_descriptor.zone_id
                || proposal.currency_genesis_root != self.currency_genesis_root
                || proposal.proposed_height >= proposal.expires_at_height
                || proposal.activate_after_height > proposal.expires_at_height
            {
                return Err("audit resource-policy proposal context or height mismatch".into());
            }
            validate_stake_state_resource_policy_v1(&proposal.proposed_policy)
                .map_err(|error| format!("audit resource policy rejected: {error}"))?;
            let commitment = stake_state_resource_policy_commitment_v1(&proposal.proposed_policy)
                .map_err(|error| {
                format!("audit resource policy commitment rejected: {error}")
            })?;
            if proposal.proposed_policy_commitment != commitment
                || proposal.proposed_policy.sequence
                    != proposal
                        .expected_current_policy_sequence
                        .checked_add(1)
                        .ok_or("audit resource-policy sequence overflow")?
                || proposal.proposed_policy.previous_policy_commitment
                    != proposal.expected_current_policy_commitment
                || proposal.subject_hash != proposal.compute_subject_hash()
            {
                return Err(
                    "audit resource-policy proposal predecessor or commitment mismatch".into(),
                );
            }
            self.verify_stake_resource_dual_quorum(
                proposal.protocol_era,
                proposal.crypto_era,
                &proposal.subject_hash,
                &proposal.validator_qc,
                &proposal.notary_qc,
            )?;
        }
        let mut resource_activation_ids = BTreeSet::new();
        let mut activated_proposal_ids = BTreeSet::new();
        let mut resource_activations = self
            .stake_resource_policy_activations
            .iter()
            .collect::<Vec<_>>();
        resource_activations.sort_by(|left, right| {
            (left.proposed_height, left.activation_id.as_str())
                .cmp(&(right.proposed_height, right.activation_id.as_str()))
        });
        let mut active_resource_policy_by_era = BTreeMap::<(u64, u64), (u64, String)>::new();
        for activation in resource_activations {
            let proposal = resource_proposals
                .get(activation.proposal_id.as_str())
                .ok_or("audit resource-policy activation has no proposal")?;
            if activation.activation_id.trim().is_empty()
                || !resource_activation_ids.insert(activation.activation_id.as_str())
                || !activated_proposal_ids.insert(activation.proposal_id.as_str())
                || activation.network_domain != proposal.network_domain
                || activation.zone_id != proposal.zone_id
                || activation.currency_genesis_root != proposal.currency_genesis_root
                || activation.protocol_era != proposal.protocol_era
                || activation.crypto_era != proposal.crypto_era
                || activation.expires_at_height != proposal.expires_at_height
                || activation.proposed_height < proposal.activate_after_height
                || activation.proposed_height > proposal.expires_at_height
                || activation.expected_pending_policy_commitment
                    != proposal.proposed_policy_commitment
                || activation.expected_current_policy_sequence
                    != proposal.expected_current_policy_sequence
                || activation.expected_current_policy_commitment
                    != proposal.expected_current_policy_commitment
                || activation.subject_hash != activation.compute_subject_hash()
            {
                return Err("audit resource-policy activation binding mismatch".into());
            }
            self.verify_stake_resource_dual_quorum(
                activation.protocol_era,
                activation.crypto_era,
                &activation.subject_hash,
                &activation.validator_qc,
                &activation.notary_qc,
            )?;
            let era = (activation.protocol_era, activation.crypto_era);
            let predecessor = active_resource_policy_by_era
                .get(&era)
                .cloned()
                .unwrap_or_else(|| (0, ZERO_SHA256.to_owned()));
            if activation.expected_current_policy_sequence != predecessor.0
                || activation.expected_current_policy_commitment != predecessor.1
            {
                return Err("audit resource-policy activation chain is discontinuous".into());
            }
            active_resource_policy_by_era.insert(
                era,
                (
                    proposal.proposed_policy.sequence,
                    proposal.proposed_policy_commitment.clone(),
                ),
            );
        }
        let current_resource_identity = active_resource_policy_by_era
            .get(&(
                self.zone_descriptor.protocol_era,
                self.zone_descriptor.crypto_era,
            ))
            .cloned();
        if let Some(pending) = &self.pending_stake_resource_policy {
            if resource_proposals
                .get(pending.proposal_id.as_str())
                .copied()
                != Some(pending)
            {
                return Err("audit pending resource policy is not immutable history".into());
            }
            let predecessor = current_resource_identity
                .clone()
                .unwrap_or_else(|| (0, ZERO_SHA256.to_owned()));
            if pending.protocol_era != self.zone_descriptor.protocol_era
                || pending.crypto_era != self.zone_descriptor.crypto_era
                || pending.expected_current_policy_sequence != predecessor.0
                || pending.expected_current_policy_commitment != predecessor.1
            {
                return Err("audit pending resource policy does not bind current state".into());
            }
        }
        if let Some(accounting) = &self.stake_resource_accounting {
            accounting
                .validate()
                .map_err(|error| format!("audit resource accounting rejected: {error}"))?;
            let identity = current_resource_identity
                .as_ref()
                .ok_or("audit resource accounting has no current-era activation")?;
            if accounting.context().network_domain != self.zone_descriptor.network_domain
                || accounting.context().zone_id != self.zone_descriptor.zone_id
                || accounting.context().currency_genesis_root != self.currency_genesis_root
                || accounting.context().protocol_era != self.zone_descriptor.protocol_era
                || accounting.context().crypto_era != self.zone_descriptor.crypto_era
                || accounting.active_policy().sequence != identity.0
                || accounting.active_policy_commitment() != identity.1
                || !accounting
                    .consumed_authorization_ids()
                    .is_subset(&self.authorization_nullifiers)
            {
                return Err(
                    "audit resource accounting context, policy or authorization mismatch".into(),
                );
            }
        } else if current_resource_identity.is_some() {
            return Err("audit current-era resource activation has no accounting state".into());
        }
        let current_horizons_empty = self.stake_position_liability_horizons.is_empty();
        let horizon_history_empty = self.stake_position_liability_horizon_history.is_empty();
        if current_horizons_empty && self.stake_liability_horizon_activation_epoch.is_some() {
            return Err("audit empty liability horizon has an activation Epoch".into());
        }
        if current_horizons_empty != horizon_history_empty
            || (!current_horizons_empty
                && self
                    .stake_liability_horizon_activation_epoch
                    .filter(|epoch| {
                        *epoch != 0
                            && self
                                .derived_stake_epochs
                                .iter()
                                .any(|record| record.descriptor.consensus_epoch == *epoch)
                    })
                    .is_none())
        {
            return Err("audit liability horizon index, history or activation diverges".into());
        }
        if !current_horizons_empty {
            let (expected_current, expected_history) =
                rebuild_stake_position_liability_horizons_v1(self.derived_stake_epochs.iter())
                    .map_err(|error| format!("audit liability horizon rebuild failed: {error}"))?;
            if self.stake_position_liability_horizons != expected_current
                || self.stake_position_liability_horizon_history != expected_history
            {
                return Err(
                    "audit liability horizons do not exactly rebuild from retained Epochs".into(),
                );
            }
        }
        if let Some(authority) = &self.consensus_stake_authority {
            validate_ledger_stake_authority_state_v1(authority)
                .map_err(|error| format!("audit stake authority rejected: {error}"))?;
        } else if !self.consensus_stake_escrows.is_empty()
            || !self.consensus_stake_unbonds.is_empty()
            || !self.consensus_stake_slashes.is_empty()
            || !self.derived_stake_epochs.is_empty()
            || !self.stake_position_liability_horizons.is_empty()
            || !self.stake_position_liability_horizon_history.is_empty()
            || self.stake_liability_horizon_activation_epoch.is_some()
        {
            return Err("audit stake records exist without a staged authority".into());
        }
        let coins = self
            .coin_history
            .iter()
            .map(|coin| (coin.object_id.as_str(), coin))
            .collect::<BTreeMap<_, _>>();
        if coins.len() != self.coin_history.len() {
            return Err("audit Coin history contains duplicate object ids".into());
        }
        if let Some(accounting) = &self.stake_resource_accounting {
            for record in accounting.bonds().values() {
                match record.resource_kind {
                    StakeStateResourceKindV1::Candidate => {
                        let validator_id = record
                            .resource_key
                            .strip_prefix("CANDIDATE/")
                            .ok_or("audit candidate resource key prefix mismatch")?;
                        let candidate = self
                            .consensus_stake_authority
                            .as_ref()
                            .and_then(|authority| {
                                authority
                                    .candidates
                                    .iter()
                                    .find(|candidate| candidate.validator_id == validator_id)
                            })
                            .ok_or("audit candidate resource has no retained candidate")?;
                        if candidate.owner != record.resource_owner {
                            return Err("audit candidate resource owner mismatch".into());
                        }
                    }
                    StakeStateResourceKindV1::Position => {
                        let position_id = record
                            .resource_key
                            .strip_prefix("POSITION/")
                            .ok_or("audit position resource key prefix mismatch")?;
                        let matches = |position: &ConsensusStakePosition| {
                            position.position_id == position_id
                                && position.owner == record.resource_owner
                                && position.slash_terms.is_some()
                        };
                        let retained = self.consensus_stake_escrows.iter().any(matches)
                            || self
                                .consensus_stake_unbonds
                                .iter()
                                .any(|unbond| matches(&unbond.position))
                            || self
                                .consensus_stake_slashes
                                .iter()
                                .any(|slash| matches(&slash.position));
                        if !retained {
                            return Err(
                                "audit position resource has no exact slashable position history"
                                    .into(),
                            );
                        }
                    }
                    StakeStateResourceKindV1::Epoch => {
                        let epoch = record
                            .resource_key
                            .strip_prefix("EPOCH/")
                            .and_then(|value| value.parse::<u64>().ok())
                            .and_then(|epoch| {
                                self.derived_stake_epochs
                                    .iter()
                                    .find(|record| record.descriptor.consensus_epoch == epoch)
                            })
                            .ok_or("audit Epoch resource has no exact retained Epoch")?;
                        let policy = accounting
                            .policy(record.resource_policy_sequence)
                            .ok_or("audit Epoch resource policy history is missing")?;
                        let authority = self
                            .consensus_stake_authority
                            .as_ref()
                            .ok_or("audit Epoch resource has no retained stake authority")?;
                        let authority_evidence_deadline = epoch
                            .descriptor
                            .exit_height
                            .checked_add(authority.policy.evidence_window_blocks)
                            .ok_or("audit Epoch evidence deadline overflow")?;
                        let evidence_deadline = epoch
                            .stake_liabilities
                            .iter()
                            .map(|liability| liability.evidence_deadline_height)
                            .max()
                            .unwrap_or(authority_evidence_deadline)
                            .max(authority_evidence_deadline);
                        let required_end = evidence_deadline
                            .checked_add(u128::from(policy.terminal_retention_blocks))
                            .ok_or("audit Epoch retention deadline overflow")?;
                        if u128::from(
                            accounting
                                .effective_lease_end_height(&record.resource_key)
                                .ok_or("audit Epoch resource lease is missing")?,
                        ) < required_end
                        {
                            return Err("audit Epoch resource lease is too short".into());
                        }
                        for validator in &epoch.descriptor.validators {
                            let dependency = accounting
                                .bonds()
                                .get(&format!("CANDIDATE/{}", validator.validator_id))
                                .ok_or("audit Epoch candidate dependency is unfunded")?;
                            if dependency.status != StakeStateBondStatusV1::Locked
                                || u128::from(
                                    accounting
                                        .effective_lease_end_height(&dependency.resource_key)
                                        .ok_or("audit candidate effective lease is missing")?,
                                ) < required_end
                            {
                                return Err(
                                    "audit Epoch candidate dependency lease is ineligible".into()
                                );
                            }
                        }
                        for liability in &epoch.stake_liabilities {
                            let dependency = accounting
                                .bonds()
                                .get(&format!("POSITION/{}", liability.position.position_id))
                                .ok_or("audit Epoch position dependency is unfunded")?;
                            if dependency.status != StakeStateBondStatusV1::Locked
                                || u128::from(
                                    accounting
                                        .effective_lease_end_height(&dependency.resource_key)
                                        .ok_or("audit position effective lease is missing")?,
                                ) < required_end
                            {
                                return Err(
                                    "audit Epoch position dependency lease is ineligible".into()
                                );
                            }
                        }
                    }
                    StakeStateResourceKindV1::Unbond | StakeStateResourceKindV1::SlashEvidence => {
                        return Err(
                            "audit accounting contains an unadopted resource lifecycle kind".into(),
                        );
                    }
                }
                let source = coins
                    .get(record.funding_source_coin_id.as_str())
                    .ok_or("audit resource funding Coin is missing")?;
                let bond = coins
                    .get(record.bond_coin_id.as_str())
                    .ok_or("audit resource bond Coin is missing")?;
                let required = record
                    .charged_creation_fee
                    .checked_add(record.locked_amount)
                    .map_err(|error| error.to_string())?;
                let change = source
                    .amount
                    .checked_sub(required)
                    .map_err(|error| error.to_string())?;
                let expected_change_id = if change.is_zero() {
                    None
                } else {
                    Some(format!(
                        "stake-state-change:{}",
                        hash_parts(&[
                            b"RLD-STAKE-STATE-RESOURCE-CHANGE-COIN-V1",
                            source.object_id.as_bytes(),
                            record.bond_id.as_bytes(),
                            &change.0.to_be_bytes(),
                        ])
                    ))
                };
                let direct_change = self.coin_history.iter().filter(|coin| {
                    coin.parent_ids == [source.object_id.clone()]
                        && coin.object_id != record.bond_coin_id
                });
                let direct_change = direct_change.collect::<Vec<_>>();
                if source.state != CoinState::Consumed
                    || source.owner != record.sponsor
                    || source.amount < required
                    || bond.owner != record.sponsor
                    || bond.amount != record.locked_amount
                    || bond.parent_ids != [source.object_id.clone()]
                    || bond.lineage_root != source.lineage_root
                    || source.version.checked_add(1) != Some(bond.version)
                    || bond.created_height != record.created_height
                    || bond.zone_id != self.zone_descriptor.zone_id
                    || bond.origin_genesis_root != self.currency_genesis_root
                    || bond.transit_id.is_some()
                    || direct_change.len() != usize::from(expected_change_id.is_some())
                    || direct_change.first().is_some_and(|coin| {
                        Some(coin.object_id.as_str()) != expected_change_id.as_deref()
                            || coin.owner != record.sponsor
                            || coin.amount != change
                            || coin.lineage_root != source.lineage_root
                            || source.version.checked_add(1) != Some(coin.version)
                            || coin.created_height != record.created_height
                            || coin.zone_id != self.zone_descriptor.zone_id
                            || coin.origin_genesis_root != self.currency_genesis_root
                            || coin.transit_id.is_some()
                    })
                {
                    return Err("audit resource admission Coin lineage mismatch".into());
                }
                let refund_children = self
                    .coin_history
                    .iter()
                    .filter(|coin| coin.parent_ids == [bond.object_id.clone()])
                    .collect::<Vec<_>>();
                match record.status {
                    StakeStateBondStatusV1::Locked | StakeStateBondStatusV1::Releaseable => {
                        if bond.state != CoinState::Reserved || !refund_children.is_empty() {
                            return Err("audit live resource bond lineage mismatch".into());
                        }
                    }
                    StakeStateBondStatusV1::Refunded => {
                        if bond.state != CoinState::Consumed
                            || refund_children.len() != 1
                            || refund_children[0].owner != record.sponsor
                            || refund_children[0].amount != record.locked_amount
                            || refund_children[0].lineage_root != bond.lineage_root
                            || bond.version.checked_add(1) != Some(refund_children[0].version)
                        {
                            return Err("audit refunded resource bond lineage mismatch".into());
                        }
                    }
                    StakeStateBondStatusV1::Forfeited => {
                        if bond.state != CoinState::Consumed || !refund_children.is_empty() {
                            return Err("audit forfeited resource bond lineage mismatch".into());
                        }
                    }
                }
            }
            for record in accounting.renewals().values() {
                let source = coins
                    .get(record.funding_source_coin_id.as_str())
                    .ok_or("audit renewal funding Coin is missing")?;
                let bond = coins
                    .get(record.bond_coin_id.as_str())
                    .ok_or("audit renewal bond Coin is missing")?;
                let required = record
                    .charged_renewal_fee
                    .checked_add(record.additional_locked_amount)
                    .map_err(|error| error.to_string())?;
                let change = source
                    .amount
                    .checked_sub(required)
                    .map_err(|error| error.to_string())?;
                let expected_change_id = if change.is_zero() {
                    None
                } else {
                    Some(format!(
                        "stake-state-renewal-change:{}",
                        hash_parts(&[
                            b"RLD-STAKE-STATE-RENEWAL-CHANGE-COIN-V1",
                            source.object_id.as_bytes(),
                            record.record_hash.as_bytes(),
                            &change.0.to_be_bytes(),
                        ])
                    ))
                };
                let children = self
                    .coin_history
                    .iter()
                    .filter(|coin| coin.parent_ids == [source.object_id.clone()])
                    .collect::<Vec<_>>();
                let expected_children = 1usize + usize::from(expected_change_id.is_some());
                let change_coin = children
                    .iter()
                    .find(|coin| coin.object_id != record.bond_coin_id);
                if source.state != CoinState::Consumed
                    || source.owner != record.sponsor
                    || bond.state != CoinState::Reserved
                    || bond.owner != record.sponsor
                    || bond.amount != record.additional_locked_amount
                    || bond.parent_ids != [source.object_id.clone()]
                    || bond.lineage_root != source.lineage_root
                    || source.version.checked_add(1) != Some(bond.version)
                    || bond.created_height != record.renewed_height
                    || bond.zone_id != self.zone_descriptor.zone_id
                    || bond.origin_genesis_root != self.currency_genesis_root
                    || bond.transit_id.is_some()
                    || children.len() != expected_children
                    || change_coin.is_some_and(|coin| {
                        Some(coin.object_id.as_str()) != expected_change_id.as_deref()
                            || coin.state != CoinState::Spendable
                            || coin.owner != record.sponsor
                            || coin.amount != change
                            || coin.lineage_root != source.lineage_root
                            || source.version.checked_add(1) != Some(coin.version)
                            || coin.created_height != record.renewed_height
                    })
                {
                    return Err("audit renewal Coin lineage mismatch".into());
                }
            }
        }
        let mut stake_position_ids = BTreeSet::new();
        let mut stake_escrow_ids = BTreeSet::new();
        let mut stake_source_ids = BTreeSet::new();
        for position in &self.consensus_stake_escrows {
            if !stake_position_ids.insert(position.position_id.as_str())
                || !stake_escrow_ids.insert(position.escrow_coin_id.as_str())
                || !stake_source_ids.insert(position.source_coin_id.as_str())
            {
                return Err("audit stake escrow registry contains duplicate ids".into());
            }
            let source = coins
                .get(position.source_coin_id.as_str())
                .ok_or_else(|| "audit stake source Coin is missing".to_string())?;
            let escrow = coins
                .get(position.escrow_coin_id.as_str())
                .ok_or_else(|| "audit stake escrow Coin is missing".to_string())?;
            if source.state != CoinState::Consumed
                || source.owner != position.owner
                || source.amount < position.amount
                || escrow.state != CoinState::Reserved
                || escrow.owner != position.owner
                || escrow.amount != position.amount
                || escrow.parent_ids != [position.source_coin_id.clone()]
                || escrow.lineage_root != source.lineage_root
                || source.version.checked_add(1) != Some(escrow.version)
                || u128::from(escrow.created_height) != position.locked_height
                || escrow.transit_id.is_some()
                || escrow.zone_id != self.zone_descriptor.zone_id
                || escrow.origin_genesis_root != self.currency_genesis_root
            {
                return Err("audit stake escrow is not an exact consumed-Coin descendant".into());
            }
        }
        let mut unbond_request_ids = BTreeSet::new();
        let mut unbond_position_ids = BTreeSet::new();
        let mut unbond_completion_ids = BTreeSet::new();
        for record in &self.consensus_stake_unbonds {
            if !unbond_request_ids.insert(record.request_id.as_str())
                || !unbond_position_ids.insert(record.position.position_id.as_str())
                || record.owner != record.position.owner
                || record.beneficiary != record.owner
                || record.request_commitment != record.compute_request_commitment()
            {
                return Err("audit stake unbond identity, owner or commitment mismatch".into());
            }
            let escrow = coins
                .get(record.position.escrow_coin_id.as_str())
                .ok_or_else(|| "audit stake unbond escrow Coin is missing".to_string())?;
            match record.status {
                ConsensusStakeUnbondStatusV1::Pending => {
                    if record.completion_id.is_some()
                        || record.completed_height.is_some()
                        || record.payout_coin_id.is_some()
                        || record.slash_id.is_some()
                        || !record.slashed_amount.is_zero()
                        || escrow.state != CoinState::Reserved
                        || !self
                            .consensus_stake_escrows
                            .iter()
                            .any(|position| position == &record.position)
                    {
                        return Err("audit pending stake unbond escrow mismatch".into());
                    }
                }
                ConsensusStakeUnbondStatusV1::Completed => {
                    let completion_id = record.completion_id.as_deref().ok_or_else(|| {
                        "audit completed stake unbond has no completion id".to_string()
                    })?;
                    if !unbond_completion_ids.insert(completion_id)
                        || record.completed_height.is_none()
                        || record.slash_id.is_some()
                        || !record.slashed_amount.is_zero()
                        || escrow.state != CoinState::Consumed
                        || self
                            .consensus_stake_escrows
                            .iter()
                            .any(|position| position == &record.position)
                    {
                        return Err("audit completed stake unbond state mismatch".into());
                    }
                    let payout = record
                        .payout_coin_id
                        .as_deref()
                        .and_then(|coin_id| coins.get(coin_id))
                        .ok_or_else(|| "audit stake unbond payout Coin is missing".to_string())?;
                    if !matches!(payout.state, CoinState::Spendable | CoinState::Consumed)
                        || payout.owner != record.beneficiary
                        || payout.amount != record.position.amount
                        || payout.parent_ids != [record.position.escrow_coin_id.clone()]
                        || payout.lineage_root != escrow.lineage_root
                        || escrow.version.checked_add(1) != Some(payout.version)
                        || Some(payout.created_height) != record.completed_height
                    {
                        return Err("audit stake unbond payout does not match its escrow".into());
                    }
                }
                ConsensusStakeUnbondStatusV1::FullySlashed => {
                    let slash_id = record
                        .slash_id
                        .as_deref()
                        .ok_or_else(|| "audit fully slashed unbond has no slash id".to_string())?;
                    if record.completion_id.is_some()
                        || record.completed_height.is_none()
                        || record.payout_coin_id.is_some()
                        || record.slashed_amount != record.position.amount
                        || escrow.state != CoinState::Consumed
                        || self
                            .consensus_stake_escrows
                            .iter()
                            .any(|position| position == &record.position)
                        || self
                            .consensus_stake_slashes
                            .iter()
                            .find(|slash| slash.slash_id == slash_id)
                            .is_none_or(|slash| slash.position != record.position)
                    {
                        return Err(
                            "audit fully slashed unbond retained value or lost slash lineage"
                                .into(),
                        );
                    }
                }
            }
        }
        let mut slash_ids = BTreeSet::new();
        let mut slash_nullifiers = BTreeSet::new();
        let mut slashed_positions = BTreeSet::new();
        let mut slash_safety_coins = BTreeSet::new();
        for record in &self.consensus_stake_slashes {
            let epoch = self.derived_stake_epochs.iter().find(|epoch| {
                epoch.descriptor.consensus_epoch == record.consensus_epoch
                    && epoch.record_hash == record.derived_epoch_record_hash
            });
            let liability = epoch.and_then(|epoch| {
                epoch
                    .stake_liabilities
                    .iter()
                    .find(|liability| liability.liability_commitment == record.liability_commitment)
            });
            let verified_evidence = epoch.and_then(|epoch| {
                verify_consensus_stake_slash_evidence_v1(
                    epoch,
                    &record.position.position_id,
                    &record.liability_commitment,
                    &record.evidence,
                )
                .ok()
            });
            if !slash_ids.insert(record.slash_id.as_str())
                || !slash_nullifiers.insert(consensus_stake_slash_nullifier_v1(
                    &record.evidence_hash,
                    &record.liability_commitment,
                ))
                || !slashed_positions.insert(record.position.position_id.as_str())
                || !slash_safety_coins.insert(record.safety_pool_coin_id.as_str())
                || record.record_hash != record.compute_record_hash()
                || record.slash_bps != 10_000
                || record.slashed_amount != record.position.amount
                || record.source_escrow_coin_id != record.position.escrow_coin_id
                || self
                    .consensus_stake_escrows
                    .iter()
                    .any(|position| position.position_id == record.position.position_id)
                || liability.is_none_or(|liability| {
                    liability.position != record.position
                        || u128::from(record.applied_height) < liability.activation_height
                        || u128::from(record.applied_height) >= liability.evidence_deadline_height
                })
                || verified_evidence.as_ref().is_none_or(|verified| {
                    verified.evidence_hash != record.evidence_hash
                        || verified.kind != record.evidence_kind
                        || verified.slash_bps != record.slash_bps
                        || verified.fault_height > u128::from(record.applied_height)
                })
            {
                return Err(
                    "audit stake slash identity, evidence, liability, amount or source mismatch"
                        .into(),
                );
            }
            let source = coins
                .get(record.source_escrow_coin_id.as_str())
                .ok_or_else(|| "audit stake slash source escrow is missing".to_string())?;
            let safety = coins
                .get(record.safety_pool_coin_id.as_str())
                .ok_or_else(|| "audit stake slash safety-pool Coin is missing".to_string())?;
            if source.state != CoinState::Consumed
                || safety.state != CoinState::Reserved
                || safety.owner != crate::CONSENSUS_SLASH_SAFETY_POOL_V2
                || safety.amount != record.slashed_amount
                || safety.parent_ids != [source.object_id.clone()]
                || safety.lineage_root != source.lineage_root
                || source.version.checked_add(1) != Some(safety.version)
                || safety.created_height != record.applied_height
                || safety.transit_id.is_some()
            {
                return Err("audit stake slash safety-pool lineage mismatch".into());
            }
        }
        if let Some(authority) = &self.consensus_stake_authority {
            for position in &authority.positions {
                if !self
                    .consensus_stake_escrows
                    .iter()
                    .any(|registered| registered == position)
                {
                    return Err("audit authority references an unregistered stake position".into());
                }
                if self
                    .consensus_stake_unbonds
                    .iter()
                    .any(|record| record.position.position_id == position.position_id)
                {
                    return Err("audit authority reintroduced an unbonding stake position".into());
                }
            }
        }
        let mut previous_epoch = None;
        for record in &self.derived_stake_epochs {
            validate_ledger_derived_stake_epoch_v1(record)
                .map_err(|error| format!("audit derived stake Epoch rejected: {error}"))?;
            if previous_epoch
                .replace(record.descriptor.consensus_epoch)
                .is_some_and(|previous| previous >= record.descriptor.consensus_epoch)
            {
                return Err("audit derived stake Epochs are not strictly ordered".into());
            }
        }
        let orders = self
            .service_orders
            .iter()
            .map(|order| (order.order_id.as_str(), order))
            .collect::<BTreeMap<_, _>>();
        let leases = self
            .service_leases
            .iter()
            .map(|lease| (lease.lease_id.as_str(), lease))
            .collect::<BTreeMap<_, _>>();
        let receipts = self
            .service_receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.as_str(), receipt))
            .collect::<BTreeMap<_, _>>();
        let commitments = self
            .protocol_reserve_commitments
            .iter()
            .map(|commitment| (commitment.order_id.as_str(), commitment))
            .collect::<BTreeMap<_, _>>();
        let controls = self
            .economic_control_attestations
            .iter()
            .map(|attestation| (attestation.attestation_id.as_str(), attestation))
            .collect::<BTreeMap<_, _>>();
        let prices = self
            .economic_price_attestations
            .iter()
            .map(|attestation| (attestation.attestation_id.as_str(), attestation))
            .collect::<BTreeMap<_, _>>();
        let policies = self
            .economic_release_policies
            .iter()
            .map(|policy| (policy.policy_id.as_str(), policy))
            .collect::<BTreeMap<_, _>>();
        let bonds = self
            .protocol_service_bonds
            .iter()
            .map(|bond| (bond.bond_id.as_str(), bond))
            .collect::<BTreeMap<_, _>>();
        if orders.len() != self.service_orders.len()
            || leases.len() != self.service_leases.len()
            || receipts.len() != self.service_receipts.len()
            || commitments.len() != self.protocol_reserve_commitments.len()
            || controls.len() != self.economic_control_attestations.len()
            || prices.len() != self.economic_price_attestations.len()
            || policies.len() != self.economic_release_policies.len()
            || bonds.len() != self.protocol_service_bonds.len()
        {
            return Err("audit bundle contains duplicate economic object IDs".into());
        }
        let mut release_ids = BTreeSet::new();
        let mut work_ids = BTreeSet::new();
        let mut completion_subjects = BTreeSet::new();
        let mut consumed_fee_receipts = BTreeSet::new();
        for release in &self.protocol_reserve_releases {
            if !release_ids.insert(release.release_id.as_str())
                || !work_ids.insert(release.work_id.as_str())
                || !completion_subjects.insert(release.completion_subject_hash.as_str())
                || release
                    .fee_receipt_ids
                    .iter()
                    .any(|id| !consumed_fee_receipts.insert(id.as_str()))
            {
                return Err(
                    "audit bundle reuses a release, work, completion QC or fee receipt".into(),
                );
            }
            let order = orders
                .get(release.order_id.as_str())
                .ok_or("economic release order is absent from audit bundle")?;
            let lease = leases
                .get(release.lease_id.as_str())
                .ok_or("economic release lease is absent from audit bundle")?;
            let receipt = receipts
                .get(release.receipt_id.as_str())
                .ok_or("economic release receipt is absent from audit bundle")?;
            let commitment = commitments
                .get(release.order_id.as_str())
                .ok_or("economic release commitment is absent from audit bundle")?;
            let control = controls
                .get(release.control_attestation_id.as_str())
                .ok_or("economic control attestation is absent from audit bundle")?;
            let policy = policies
                .get(release.release_policy_id.as_str())
                .ok_or("economic release policy is absent from audit bundle")?;
            let bond = bonds
                .get(release.bond_id.as_str())
                .ok_or("economic service bond is absent from audit bundle")?;
            if order.status != ServiceStatus::Completed
                || lease.order_id != order.order_id
                || receipt.order_id != order.order_id
                || receipt.lease_id != lease.lease_id
                || receipt.node_id != lease.node_id
                || receipt.amount != release.reward
                || receipt.proof_hash != release.work_proof_hash
                || receipt.protocol_reserve_pool != Some(release.reserve_pool)
                || commitment.reserve_pool != release.reserve_pool
                || commitment.settled_amount != Some(release.reward)
                || policy.reserve_pool != release.reserve_pool
                || policy.era_id != release.era_id
                || policy.era_release_cap != release.era_release_cap
                || bond.order_id != release.order_id
                || bond.lease_id != release.lease_id
                || bond.provider_node_id != lease.node_id
            {
                return Err("economic release object linkage is inconsistent".into());
            }
            if release.completion_validator_qc.subject_hash != release.completion_subject_hash
                || release.completion_notary_qc.subject_hash != release.completion_subject_hash
                || release.completion_subject_hash != release.expected_completion_subject_hash()
                || release.work_id
                    != ProtocolReserveReleaseRequest::derive_work_id(
                        &release.requester_subject_id,
                        &release.work_proof_hash,
                    )
                || release.completion_validator_qc.testnet_simulated
                || release.completion_notary_qc.testnet_simulated
            {
                return Err("economic completion QCs are not auditable".into());
            }
            release
                .completion_validator_qc
                .verify(&self.zone_descriptor.validator_keys)?;
            release
                .completion_notary_qc
                .verify(&self.zone_descriptor.notary_keys)?;
            let control_subject = control.subject_hash();
            verify_bytes(
                &control.auditor_public_key,
                control_subject.as_bytes(),
                &control.auditor_signature,
            )?;
            if control.validator_qc.subject_hash != control_subject
                || control.notary_qc.subject_hash != control_subject
            {
                return Err("economic control QCs do not bind the persisted subject".into());
            }
            control
                .validator_qc
                .verify(&self.zone_descriptor.validator_keys)?;
            control
                .notary_qc
                .verify(&self.zone_descriptor.notary_keys)?;
            let policy_subject = policy.subject_hash();
            if policy.validator_qc.subject_hash != policy_subject
                || policy.notary_qc.subject_hash != policy_subject
            {
                return Err("economic policy QCs do not bind the persisted subject".into());
            }
            policy
                .validator_qc
                .verify(&self.zone_descriptor.validator_keys)?;
            policy.notary_qc.verify(&self.zone_descriptor.notary_keys)?;
            let mut price_groups = BTreeSet::new();
            let mut price_cap: Option<Amount> = None;
            for price_id in &release.price_attestation_ids {
                let price = prices
                    .get(price_id.as_str())
                    .ok_or("economic price attestation is absent from audit bundle")?;
                if price.work_id != release.work_id
                    || price.control_attestation_id != release.control_attestation_id
                    || price.issued_height > release.released_height
                    || price.valid_until_height <= release.released_height
                {
                    return Err("economic price attestation release binding is invalid".into());
                }
                verify_bytes(
                    &price.source_public_key,
                    price.subject_hash().as_bytes(),
                    &price.signature,
                )?;
                price_groups.insert(price.source_control_group_id.as_str());
                price_cap = Some(match price_cap {
                    Some(cap) if cap <= price.amount => cap,
                    _ => price.amount,
                });
            }
            if price_groups.len() < 2 || price_cap != Some(release.independent_price_cap) {
                return Err("economic release lacks two independent price groups".into());
            }
            let mut attributable_fee = Amount::ZERO;
            for fee_receipt_id in &release.fee_receipt_ids {
                let fee_receipt = receipts
                    .get(fee_receipt_id.as_str())
                    .ok_or("economic fee receipt is absent from audit bundle")?;
                let fee_order = orders
                    .get(fee_receipt.order_id.as_str())
                    .ok_or("economic fee order is absent from audit bundle")?;
                if fee_receipt.bootstrap
                    || fee_receipt.protocol_reserve_pool.is_some()
                    || fee_receipt.proof_hash != release.work_proof_hash
                    || fee_order.buyer != release.requester_subject_id
                    || fee_order.status != ServiceStatus::Completed
                {
                    return Err("economic fee attribution is invalid".into());
                }
                attributable_fee = attributable_fee
                    .checked_add(fee_receipt.amount)
                    .map_err(|error| error.to_string())?;
            }
            let computed_nonrecoverable = release
                .attributable_fee
                .checked_sub(release.affiliated_recovery)
                .map_err(|error| error.to_string())?;
            let bond_multiplier = u128::from(release.minimum_bond_coverage_bps);
            let bond_divisor = 10_000u128;
            let bond_whole = (release.reward.0 / bond_divisor)
                .checked_mul(bond_multiplier)
                .ok_or("economic bond coverage calculation overflow")?;
            let bond_remainder = (release.reward.0 % bond_divisor)
                .checked_mul(bond_multiplier)
                .and_then(|value| value.checked_add(bond_divisor - 1))
                .map(|value| value / bond_divisor)
                .ok_or("economic bond coverage calculation overflow")?;
            let required_bond = bond_whole
                .checked_add(bond_remainder)
                .ok_or("economic bond coverage calculation overflow")?;
            let released_after = release
                .era_released_before
                .checked_add(release.reward)
                .map_err(|error| error.to_string())?;
            if attributable_fee != release.attributable_fee
                || computed_nonrecoverable != release.nonrecoverable_fee
                || release.reward > release.nonrecoverable_fee
                || release.reward > release.independent_price_cap
                || release.reward > release.pool_balance_before
                || released_after > release.era_release_cap
                || release.minimum_bond_coverage_bps < MIN_PROTOCOL_SERVICE_BOND_COVERAGE_BPS
                || release.bond_locked_amount.0 < required_bond
                || release.bond_slashable_amount.0 < required_bond
                || release.bond_slashable_amount > release.bond_locked_amount
                || release.released_height >= release.bond_challenge_end_height
                || release.bond_unbond_after_height <= release.bond_challenge_end_height
            {
                return Err("economic release arithmetic or safety bounds are invalid".into());
            }
        }
        if self.compute_commitment()? != self.commitment_hash {
            return Err("audit bundle commitment mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CausalEnvelope {
    pub envelope_id: String,
    pub parent_ids: Vec<String>,
    pub object_id: String,
    pub object_version: u64,
    pub source_checkpoint: String,
    pub transport: TransportClass,
    pub payload_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceRole {
    Validator,
    Notary,
    Relay,
    Storage,
    Archive,
    Gateway,
    Liquidity,
    ContinuityCustodian,
    FtlGateway,
    Observer,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceStatus {
    Open,
    Leased,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolReservePoolKind {
    StartupServices,
    ContinuityServices,
    DemandMatching,
}

impl ProtocolReservePoolKind {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::StartupServices => "STARTUP_SERVICES",
            Self::ContinuityServices => "CONTINUITY_SERVICES",
            Self::DemandMatching => "DEMAND_MATCHING",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolServiceOrderRequest {
    pub request_id: String,
    pub zone_id: String,
    pub reserve_pool: ProtocolReservePoolKind,
    pub role: ServiceRole,
    pub budget: Amount,
    pub description: String,
    pub matched_service_receipt_id: Option<String>,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub nonce: u64,
    pub subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl ProtocolServiceOrderRequest {
    pub fn compute_subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-PROTOCOL-SERVICE-ORDER-V1",
            self.request_id.as_bytes(),
            self.zone_id.as_bytes(),
            self.reserve_pool.wire_name().as_bytes(),
            format!("{:?}", self.role).to_uppercase().as_bytes(),
            &self.budget.0.to_be_bytes(),
            self.description.as_bytes(),
            self.matched_service_receipt_id
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
            &self.nonce.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolReserveCommitment {
    pub order_id: String,
    pub reserve_pool: ProtocolReservePoolKind,
    pub committed_amount: Amount,
    pub matched_service_receipt_id: Option<String>,
    pub authorization_subject_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
    #[serde(default)]
    pub settled_amount: Option<Amount>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolServiceCompletionClaim {
    pub zone_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub node_id: String,
    pub role: ServiceRole,
    pub amount: Amount,
    pub proof_hash: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
}

impl ProtocolServiceCompletionClaim {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-PROTOCOL-SERVICE-COMPLETION-V1",
            self.zone_id.as_bytes(),
            self.order_id.as_bytes(),
            self.lease_id.as_bytes(),
            self.node_id.as_bytes(),
            format!("{:?}", self.role).to_uppercase().as_bytes(),
            &self.amount.0.to_be_bytes(),
            self.proof_hash.as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceOrder {
    pub order_id: String,
    pub buyer: String,
    pub role: ServiceRole,
    pub budget: Amount,
    pub escrow_coin_id: String,
    pub description: String,
    pub status: ServiceStatus,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceLease {
    pub lease_id: String,
    pub order_id: String,
    pub node_id: String,
    pub accepted_quote: Amount,
    pub accepted_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceReceipt {
    pub receipt_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub node_id: String,
    pub role: ServiceRole,
    pub amount: Amount,
    pub proof_hash: String,
    pub completed_height: u64,
    pub bootstrap: bool,
    #[serde(default)]
    pub protocol_reserve_pool: Option<ProtocolReservePoolKind>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeEarnings {
    pub node_id: String,
    pub total: Amount,
    pub by_role: BTreeMap<String, Amount>,
    pub receipt_ids: Vec<String>,
}

pub const MAX_ECONOMIC_CONTROL_GROUP_VALIDATOR_BPS: u32 = 3_333;
pub const MIN_PROTOCOL_SERVICE_BOND_COVERAGE_BPS: u32 = 20_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EconomicControlRole {
    Requester,
    ServiceProvider,
    Relay,
    LiquidityProvider,
    Validator,
    Notary,
    PriceSource,
}

impl EconomicControlRole {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Requester => "REQUESTER",
            Self::ServiceProvider => "SERVICE_PROVIDER",
            Self::Relay => "RELAY",
            Self::LiquidityProvider => "LIQUIDITY_PROVIDER",
            Self::Validator => "VALIDATOR",
            Self::Notary => "NOTARY",
            Self::PriceSource => "PRICE_SOURCE",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicControlMember {
    pub subject_id: String,
    pub control_group_id: String,
    pub role: EconomicControlRole,
    pub validator_vote_bps: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicControlAttestation {
    pub attestation_id: String,
    pub zone_id: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub issued_height: u64,
    pub valid_until_height: u64,
    pub evidence_hash: String,
    pub auditor_public_key: String,
    pub auditor_control_group_id: String,
    pub members: Vec<EconomicControlMember>,
    pub auditor_signature: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl EconomicControlAttestation {
    pub fn subject_hash(&self) -> String {
        let mut bytes = b"RLD-ECONOMIC-CONTROL-ATTESTATION-V1".to_vec();
        put_string(&mut bytes, &self.attestation_id);
        put_string(&mut bytes, &self.zone_id);
        bytes.extend_from_slice(&self.protocol_era.to_be_bytes());
        bytes.extend_from_slice(&self.crypto_era.to_be_bytes());
        bytes.extend_from_slice(&self.issued_height.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until_height.to_be_bytes());
        put_string(&mut bytes, &self.evidence_hash);
        put_string(&mut bytes, &self.auditor_public_key);
        put_string(&mut bytes, &self.auditor_control_group_id);
        for member in &self.members {
            put_string(&mut bytes, &member.subject_id);
            put_string(&mut bytes, &member.control_group_id);
            put_string(&mut bytes, member.role.wire_name());
            bytes.extend_from_slice(&member.validator_vote_bps.to_be_bytes());
        }
        hash_bytes(&bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicPriceAttestation {
    pub attestation_id: String,
    pub zone_id: String,
    pub work_id: String,
    pub control_attestation_id: String,
    pub source_public_key: String,
    pub source_control_group_id: String,
    pub amount: Amount,
    pub issued_height: u64,
    pub valid_until_height: u64,
    pub evidence_hash: String,
    pub signature: String,
}

impl EconomicPriceAttestation {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-ECONOMIC-PRICE-ATTESTATION-V1",
            self.attestation_id.as_bytes(),
            self.zone_id.as_bytes(),
            self.work_id.as_bytes(),
            self.control_attestation_id.as_bytes(),
            self.source_public_key.as_bytes(),
            self.source_control_group_id.as_bytes(),
            &self.amount.0.to_be_bytes(),
            &self.issued_height.to_be_bytes(),
            &self.valid_until_height.to_be_bytes(),
            self.evidence_hash.as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EconomicReleasePolicy {
    pub policy_id: String,
    pub zone_id: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub era_id: String,
    pub reserve_pool: ProtocolReservePoolKind,
    pub era_release_cap: Amount,
    pub released: Amount,
    pub starts_at_height: u64,
    pub ends_after_height: u64,
    pub minimum_bond_coverage_bps: u32,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl EconomicReleasePolicy {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-ECONOMIC-RELEASE-POLICY-V1",
            self.policy_id.as_bytes(),
            self.zone_id.as_bytes(),
            &self.protocol_era.to_be_bytes(),
            &self.crypto_era.to_be_bytes(),
            self.era_id.as_bytes(),
            self.reserve_pool.wire_name().as_bytes(),
            &self.era_release_cap.0.to_be_bytes(),
            &self.starts_at_height.to_be_bytes(),
            &self.ends_after_height.to_be_bytes(),
            &self.minimum_bond_coverage_bps.to_be_bytes(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolServiceBondStatus {
    Locked,
    PartiallySlashed,
    FullySlashed,
    Unbonded,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolServiceBond {
    pub bond_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub owner: String,
    pub provider_node_id: String,
    pub escrow_coin_id: Option<String>,
    pub locked_amount: Amount,
    pub slashable_remaining: Amount,
    pub slashed_amount: Amount,
    pub slashed_coin_ids: Vec<String>,
    pub challenge_end_height: u64,
    pub unbond_after_height: u64,
    pub slash_conditions_hash: String,
    pub created_height: u64,
    pub status: ProtocolServiceBondStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolServiceBondLockRequest {
    pub bond_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub owner: String,
    pub coin_id: String,
    pub amount: Amount,
    pub challenge_end_height: u64,
    pub unbond_after_height: u64,
    pub slash_conditions_hash: String,
    pub authorization: SignedActionAuthorization,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolServiceBondSlash {
    pub slash_id: String,
    pub bond_id: String,
    pub amount: Amount,
    pub evidence_hash: String,
    pub validator_qc: QuorumCertificate,
    pub notary_qc: QuorumCertificate,
}

impl ProtocolServiceBondSlash {
    pub fn subject_hash(&self) -> String {
        hash_parts(&[
            b"RLD-PROTOCOL-SERVICE-BOND-SLASH-V1",
            self.slash_id.as_bytes(),
            self.bond_id.as_bytes(),
            &self.amount.0.to_be_bytes(),
            self.evidence_hash.as_bytes(),
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolReserveReleaseRequest {
    pub release_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub requester_subject_id: String,
    pub work_id: String,
    pub work_proof_hash: String,
    pub fee_receipt_ids: Vec<String>,
    pub control_attestation_id: String,
    pub price_attestation_ids: Vec<String>,
    pub bond_id: String,
    pub release_policy_id: String,
    pub reward: Amount,
    pub provider_authorization: SignedActionAuthorization,
    pub completion_validator_qc: QuorumCertificate,
    pub completion_notary_qc: QuorumCertificate,
}

impl ProtocolReserveReleaseRequest {
    pub fn derive_work_id(requester_subject_id: &str, work_proof_hash: &str) -> String {
        hash_parts(&[
            b"RLD-ECONOMIC-WORK-ID-V1",
            requester_subject_id.as_bytes(),
            work_proof_hash.as_bytes(),
        ])
    }

    pub fn completion_subject_hash(&self) -> String {
        let mut bytes = b"RLD-PROTOCOL-RESERVE-RELEASE-COMPLETION-V1".to_vec();
        put_string(&mut bytes, &self.order_id);
        put_string(&mut bytes, &self.lease_id);
        put_string(&mut bytes, &self.requester_subject_id);
        put_string(&mut bytes, &self.work_id);
        put_string(&mut bytes, &self.work_proof_hash);
        for receipt_id in &self.fee_receipt_ids {
            put_string(&mut bytes, receipt_id);
        }
        put_string(&mut bytes, &self.control_attestation_id);
        for price_id in &self.price_attestation_ids {
            put_string(&mut bytes, price_id);
        }
        put_string(&mut bytes, &self.bond_id);
        put_string(&mut bytes, &self.release_policy_id);
        bytes.extend_from_slice(&self.reward.0.to_be_bytes());
        hash_bytes(&bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolReserveReleaseRecord {
    pub release_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub receipt_id: String,
    pub requester_subject_id: String,
    pub work_id: String,
    pub work_proof_hash: String,
    pub completion_subject_hash: String,
    pub completion_validator_qc: QuorumCertificate,
    pub completion_notary_qc: QuorumCertificate,
    pub fee_receipt_ids: Vec<String>,
    pub control_attestation_id: String,
    pub price_attestation_ids: Vec<String>,
    pub bond_id: String,
    pub bond_locked_amount: Amount,
    pub bond_slashable_amount: Amount,
    pub bond_slashed_amount: Amount,
    pub bond_challenge_end_height: u64,
    pub bond_unbond_after_height: u64,
    pub bond_slash_conditions_hash: String,
    pub release_policy_id: String,
    pub era_id: String,
    pub era_release_cap: Amount,
    pub era_released_before: Amount,
    pub pool_balance_before: Amount,
    pub minimum_bond_coverage_bps: u32,
    pub reserve_pool: ProtocolReservePoolKind,
    pub attributable_fee: Amount,
    pub affiliated_recovery: Amount,
    pub nonrecoverable_fee: Amount,
    pub independent_price_cap: Amount,
    pub reward: Amount,
    pub released_height: u64,
}

impl ProtocolReserveReleaseRecord {
    pub fn expected_completion_subject_hash(&self) -> String {
        let mut bytes = b"RLD-PROTOCOL-RESERVE-RELEASE-COMPLETION-V1".to_vec();
        put_string(&mut bytes, &self.order_id);
        put_string(&mut bytes, &self.lease_id);
        put_string(&mut bytes, &self.requester_subject_id);
        put_string(&mut bytes, &self.work_id);
        put_string(&mut bytes, &self.work_proof_hash);
        for receipt_id in &self.fee_receipt_ids {
            put_string(&mut bytes, receipt_id);
        }
        put_string(&mut bytes, &self.control_attestation_id);
        for price_id in &self.price_attestation_ids {
            put_string(&mut bytes, price_id);
        }
        put_string(&mut bytes, &self.bond_id);
        put_string(&mut bytes, &self.release_policy_id);
        bytes.extend_from_slice(&self.reward.0.to_be_bytes());
        hash_bytes(&bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VoyageStatus {
    Open,
    Completed,
    RouteExhausted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdaptiveVoyageEscrow {
    pub voyage_id: String,
    pub transit_id: String,
    pub payer: String,
    pub destination_zone: String,
    pub original_budget: Amount,
    pub remaining_budget: Amount,
    pub max_reward_per_hop: Amount,
    pub escrow_coin_id: Option<String>,
    pub settled_proof_hashes: Vec<String>,
    pub status: VoyageStatus,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoyageServiceReceipt {
    pub receipt_id: String,
    pub voyage_id: String,
    pub transit_id: String,
    pub node_id: String,
    pub amount: Amount,
    pub downstream_receipt_hash: String,
    pub completed_height: u64,
}

#[cfg(test)]
mod consensus_height_tests {
    use super::*;

    fn proposal(parent_height: u64, expected_height: u64) -> ConsensusProposal {
        let command = ConsensusCommand::ActivatePendingValueRiskPolicy;
        ConsensusProposal {
            proposal_id: "proposal-height-boundary".into(),
            zone_id: "zone-height-boundary".into(),
            currency_genesis_root: "genesis-height-boundary".into(),
            protocol_era: 1,
            crypto_era: 1,
            parent_height,
            parent_state_root: "parent-root".into(),
            round: 0,
            proposer_public_key: "not-reached-because-height-is-invalid".into(),
            command_hash: command.command_hash(),
            command,
            expected_height,
            expected_state_root: "expected-root".into(),
            signature: "not-reached-because-height-is-invalid".into(),
        }
    }

    #[test]
    fn proposal_rejects_parent_height_overflow_instead_of_saturating() {
        let error = proposal(u64::MAX, u64::MAX).verify().unwrap_err();
        assert_eq!(error, "consensus proposal parent height overflow");
    }

    #[test]
    fn wire_v1_proposal_rejects_runtime_height_wrap_before_signature_work() {
        let mut proposal = proposal(u64::MAX, 0);
        proposal.command_hash = proposal
            .command
            .wire_v1_command_hash(RLDCOIN_MAINNET_DOMAIN)
            .unwrap();
        let error = proposal.verify_wire_v1(RLDCOIN_MAINNET_DOMAIN).unwrap_err();
        assert_eq!(error.code, "height_overflow");
    }

    #[test]
    fn proposal_still_requires_exactly_one_height_advance() {
        let error = proposal(41, 43).verify().unwrap_err();
        assert_eq!(error, "consensus proposal must advance exactly one height");
    }

    #[test]
    fn quorum_formula_is_exact_without_saturating_at_usize_max() {
        for (members, expected) in [(1, 1), (2, 2), (3, 3), (4, 3), (5, 4), (6, 5)] {
            assert_eq!(required_quorum(members), Ok(expected));
        }
        let maximum = usize::MAX;
        assert_eq!(required_quorum(maximum), Ok(maximum - (maximum - 1) / 3));
    }

    #[test]
    fn round_zero_leader_is_order_independent_and_rejects_duplicates() {
        let mut keys = vec![
            "validator-c".into(),
            "validator-a".into(),
            "validator-b".into(),
        ];
        let expected = deterministic_round_zero_leader(&keys, 17).unwrap();
        keys.reverse();
        assert_eq!(
            deterministic_round_zero_leader(&keys, 17).unwrap(),
            expected
        );
        assert!(
            deterministic_round_zero_leader(&["validator-a".into(), "validator-a".into()], 0)
                .is_err()
        );
    }
}
