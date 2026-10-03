use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::crypto::{hash_bytes, validate_ed25519_public_key};
use crate::types::{RLDCOIN_MAINNET_DOMAIN, RLDCOIN_TESTNET_DOMAIN};

const COMMITMENT_DOMAIN_V1: &[u8] = b"RLD-CONSENSUS-EPOCH-DESCRIPTOR-V1\0";
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CONTROL_GROUP_BYTES: usize = 128;

pub const MIN_VALIDATORS_PER_EPOCH: usize = 4;
pub const MAX_VALIDATORS_PER_EPOCH: usize = 4096;
pub const MAX_CONSENSUS_EPOCH_DESCRIPTOR_BYTES: usize = 4 * 1024 * 1024;

pub const QUORUM_RULE_VERSION_V1: u16 = 1;
pub const QUORUM_NUMERATOR_V1: u64 = 2;
pub const QUORUM_DENOMINATOR_V1: u64 = 3;

/// The exact quorum semantics committed into a consensus epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusQuorumRule {
    pub version: u16,
    pub numerator: u64,
    pub denominator: u64,
    pub strict_supermajority: bool,
}

impl ConsensusQuorumRule {
    pub const fn v1() -> Self {
        Self {
            version: QUORUM_RULE_VERSION_V1,
            numerator: QUORUM_NUMERATOR_V1,
            denominator: QUORUM_DENOMINATOR_V1,
            strict_supermajority: true,
        }
    }

    fn validate(&self) -> Result<(), ConsensusEpochError> {
        if self != &Self::v1() {
            return Err(ConsensusEpochError::UnsupportedQuorumRule);
        }
        Ok(())
    }
}

impl Default for ConsensusQuorumRule {
    fn default() -> Self {
        Self::v1()
    }
}

/// Validator material frozen for one consensus epoch.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRecord {
    pub validator_id: String,
    pub public_key: String,
    pub key_era: u64,
    pub weight: u128,
    pub control_group: String,
    pub self_bond: u128,
    pub delegated_weight: u128,
    pub unbonding_height: u128,
}

/// Structurally verifiable candidate for one consensus epoch.
///
/// Validation and hashing do **not** prove that the declared stake or control
/// groups came from authoritative consensus state. Until the ledger can
/// independently reconstruct every record from `stake_snapshot_root`, this
/// type must not authorize proposals, votes, certificates, or value.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ConsensusEpochDescriptor {
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis_root: String,
    pub protocol_era: u64,
    pub crypto_era: u64,
    pub consensus_protocol_version: u64,
    pub consensus_epoch: u64,
    pub activation_height: u128,
    /// Exclusive height at which this descriptor is no longer active.
    pub exit_height: u128,
    pub stake_snapshot_root: String,
    pub validators: Vec<ValidatorRecord>,
    pub total_weight: u128,
    pub quorum_power: u128,
    pub quorum_rule: ConsensusQuorumRule,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConsensusEpochDescriptor {
    network_domain: String,
    zone_id: String,
    currency_genesis_root: String,
    protocol_era: u64,
    crypto_era: u64,
    consensus_protocol_version: u64,
    consensus_epoch: u64,
    activation_height: u128,
    exit_height: u128,
    stake_snapshot_root: String,
    #[serde(deserialize_with = "deserialize_bounded_validators")]
    validators: Vec<ValidatorRecord>,
    total_weight: u128,
    quorum_power: u128,
    quorum_rule: ConsensusQuorumRule,
}

impl From<RawConsensusEpochDescriptor> for ConsensusEpochDescriptor {
    fn from(raw: RawConsensusEpochDescriptor) -> Self {
        Self {
            network_domain: raw.network_domain,
            zone_id: raw.zone_id,
            currency_genesis_root: raw.currency_genesis_root,
            protocol_era: raw.protocol_era,
            crypto_era: raw.crypto_era,
            consensus_protocol_version: raw.consensus_protocol_version,
            consensus_epoch: raw.consensus_epoch,
            activation_height: raw.activation_height,
            exit_height: raw.exit_height,
            stake_snapshot_root: raw.stake_snapshot_root,
            validators: raw.validators,
            total_weight: raw.total_weight,
            quorum_power: raw.quorum_power,
            quorum_rule: raw.quorum_rule,
        }
    }
}

impl<'de> Deserialize<'de> for ConsensusEpochDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let descriptor = Self::from(RawConsensusEpochDescriptor::deserialize(deserializer)?);
        descriptor.validate().map_err(de::Error::custom)?;
        Ok(descriptor)
    }
}

/// Type-separated digest for the candidate epoch descriptor. It cannot be
/// confused in Rust with the frozen `030f ConsensusValidatorSet` digest.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ConsensusEpochDescriptorCommitment(String);

impl ConsensusEpochDescriptorCommitment {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConsensusEpochError {
    #[error("unsupported network domain")]
    InvalidNetworkDomain,
    #[error("invalid zone id")]
    InvalidZoneId,
    #[error("{0} must be canonical lowercase 32-byte hex")]
    InvalidHash(&'static str),
    #[error("activation height must be lower than exit height")]
    InvalidHeightWindow,
    #[error("parent height is outside the consensus epoch validity window")]
    InactiveAtParentHeight,
    #[error("consensus protocol version must be nonzero")]
    ZeroConsensusProtocolVersion,
    #[error("validator count must be between 4 and 4096")]
    ValidatorCountOutOfRange,
    #[error("invalid validator id: {0}")]
    InvalidValidatorId(String),
    #[error("duplicate validator id: {0}")]
    DuplicateValidatorId(String),
    #[error("duplicate validator public key: {0}")]
    DuplicatePublicKey(String),
    #[error("invalid public key for validator {validator_id}: {reason}")]
    InvalidPublicKey {
        validator_id: String,
        reason: String,
    },
    #[error("validator {0} has zero weight")]
    ZeroWeight(String),
    #[error("validator {0} has zero self bond")]
    ZeroSelfBond(String),
    #[error("invalid control group for validator {0}")]
    InvalidControlGroup(String),
    #[error("weight components overflow for validator {0}")]
    ValidatorWeightOverflow(String),
    #[error("control-group weight overflows u128")]
    ControlGroupWeightOverflow,
    #[error("weight does not equal self bond plus delegated weight for validator {0}")]
    ValidatorWeightMismatch(String),
    #[error("total validator weight overflows u128")]
    TotalWeightOverflow,
    #[error("declared total weight {declared} does not equal computed total {computed}")]
    TotalWeightMismatch { declared: u128, computed: u128 },
    #[error("total weight must be nonzero")]
    ZeroTotalWeight,
    #[error("declared quorum power {declared} does not equal computed quorum {computed}")]
    QuorumPowerMismatch { declared: u128, computed: u128 },
    #[error("unsupported quorum rule or parameters")]
    UnsupportedQuorumRule,
    #[error("validator records are not in strict canonical order")]
    NonCanonicalValidatorOrder,
    #[error("control group {control_group} has weight {weight}, above tolerated {maximum}")]
    ControlGroupWeightTooHigh {
        control_group: String,
        weight: u128,
        maximum: u128,
    },
    #[error("validator {0} can unbond before the epoch validity window closes")]
    UnbondingBeforeEpochExit(String),
    #[error("canonical field exceeds the u32 length limit")]
    FieldTooLarge,
    #[error("consensus epoch descriptor exceeds the 4 MiB input limit")]
    DescriptorTooLarge,
    #[error("invalid consensus epoch descriptor JSON: {0}")]
    InvalidJson(String),
}

/// The only supported JSON decoder for an untrusted descriptor. The raw body
/// is bounded before serde can allocate strings or member records, and the
/// result is structurally validated before release.
pub fn decode_consensus_epoch_descriptor_json(
    bytes: &[u8],
) -> Result<ConsensusEpochDescriptor, ConsensusEpochError> {
    if bytes.len() > MAX_CONSENSUS_EPOCH_DESCRIPTOR_BYTES {
        return Err(ConsensusEpochError::DescriptorTooLarge);
    }
    let raw: RawConsensusEpochDescriptor = serde_json::from_slice(bytes)
        .map_err(|error| ConsensusEpochError::InvalidJson(error.to_string()))?;
    let descriptor = ConsensusEpochDescriptor::from(raw);
    descriptor.validate()?;
    Ok(descriptor)
}

impl ConsensusEpochDescriptor {
    pub fn validate(&self) -> Result<(), ConsensusEpochError> {
        validated_canonical_validators(self).map(|_| ())
    }

    pub fn validate_for_parent_height(
        &self,
        parent_height: u128,
    ) -> Result<(), ConsensusEpochError> {
        self.validate()?;
        if parent_height < self.activation_height || parent_height >= self.exit_height {
            return Err(ConsensusEpochError::InactiveAtParentHeight);
        }
        Ok(())
    }

    pub fn descriptor_commitment_v1(
        &self,
    ) -> Result<ConsensusEpochDescriptorCommitment, ConsensusEpochError> {
        consensus_epoch_descriptor_commitment_v1(self)
    }
}

/// Computes the v1 quorum threshold: strictly more than two thirds of total
/// voting power, written without multiplication that could overflow u128.
pub fn quorum_power_v1(total_weight: u128) -> Result<u128, ConsensusEpochError> {
    let total_minus_one = total_weight
        .checked_sub(1)
        .ok_or(ConsensusEpochError::ZeroTotalWeight)?;
    total_weight
        .checked_sub(total_minus_one / 3)
        .ok_or(ConsensusEpochError::ZeroTotalWeight)
}

/// Returns the SHA-256 commitment to the complete, validated epoch descriptor.
/// This is a candidate internal commitment and is deliberately not the frozen
/// `030f ConsensusValidatorSet` subject digest used by current wire messages.
pub fn consensus_epoch_descriptor_commitment_v1(
    descriptor: &ConsensusEpochDescriptor,
) -> Result<ConsensusEpochDescriptorCommitment, ConsensusEpochError> {
    Ok(ConsensusEpochDescriptorCommitment(hash_bytes(
        &consensus_epoch_commitment_bytes_v1(descriptor)?,
    )))
}

fn deserialize_bounded_validators<'de, D>(deserializer: D) -> Result<Vec<ValidatorRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedValidatorVisitor;

    impl<'de> Visitor<'de> for BoundedValidatorVisitor {
        type Value = Vec<ValidatorRecord>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "between {MIN_VALIDATORS_PER_EPOCH} and {MAX_VALIDATORS_PER_EPOCH} validators"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_VALIDATORS_PER_EPOCH)
            {
                return Err(de::Error::custom("validator list exceeds 4096 members"));
            }
            let mut validators = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(MIN_VALIDATORS_PER_EPOCH)
                    .min(MAX_VALIDATORS_PER_EPOCH),
            );
            while validators.len() < MAX_VALIDATORS_PER_EPOCH {
                let Some(validator) = sequence.next_element()? else {
                    return Ok(validators);
                };
                validators.push(validator);
            }
            if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("validator list exceeds 4096 members"));
            }
            Ok(validators)
        }
    }

    deserializer.deserialize_seq(BoundedValidatorVisitor)
}

/// Deterministic binary preimage for
/// [`consensus_epoch_descriptor_commitment_v1`].
pub fn consensus_epoch_commitment_bytes_v1(
    descriptor: &ConsensusEpochDescriptor,
) -> Result<Vec<u8>, ConsensusEpochError> {
    let validators = validated_canonical_validators(descriptor)?;
    let currency_genesis_root =
        decode_hash32("currency_genesis_root", &descriptor.currency_genesis_root)?;
    let stake_snapshot_root =
        decode_hash32("stake_snapshot_root", &descriptor.stake_snapshot_root)?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(COMMITMENT_DOMAIN_V1);
    push_field(&mut encoded, 1, descriptor.network_domain.as_bytes())?;
    push_field(&mut encoded, 2, descriptor.zone_id.as_bytes())?;
    push_field(&mut encoded, 3, &currency_genesis_root)?;
    push_field(&mut encoded, 4, &descriptor.protocol_era.to_be_bytes())?;
    push_field(&mut encoded, 5, &descriptor.crypto_era.to_be_bytes())?;
    push_field(
        &mut encoded,
        6,
        &descriptor.consensus_protocol_version.to_be_bytes(),
    )?;
    push_field(&mut encoded, 7, &descriptor.consensus_epoch.to_be_bytes())?;
    push_field(&mut encoded, 8, &descriptor.activation_height.to_be_bytes())?;
    push_field(&mut encoded, 9, &descriptor.exit_height.to_be_bytes())?;
    push_field(&mut encoded, 10, &stake_snapshot_root)?;

    let mut member_bytes = Vec::new();
    member_bytes.extend_from_slice(
        &u32::try_from(validators.len())
            .map_err(|_| ConsensusEpochError::FieldTooLarge)?
            .to_be_bytes(),
    );
    for validator in validators {
        let record = encode_validator(validator)?;
        member_bytes.extend_from_slice(
            &u32::try_from(record.len())
                .map_err(|_| ConsensusEpochError::FieldTooLarge)?
                .to_be_bytes(),
        );
        member_bytes.extend_from_slice(&record);
    }
    push_field(&mut encoded, 11, &member_bytes)?;
    push_field(&mut encoded, 12, &descriptor.total_weight.to_be_bytes())?;
    push_field(&mut encoded, 13, &descriptor.quorum_power.to_be_bytes())?;
    push_field(
        &mut encoded,
        14,
        &descriptor.quorum_rule.version.to_be_bytes(),
    )?;
    push_field(
        &mut encoded,
        15,
        &descriptor.quorum_rule.numerator.to_be_bytes(),
    )?;
    push_field(
        &mut encoded,
        16,
        &descriptor.quorum_rule.denominator.to_be_bytes(),
    )?;
    push_field(
        &mut encoded,
        17,
        &[u8::from(descriptor.quorum_rule.strict_supermajority)],
    )?;
    Ok(encoded)
}

fn validated_canonical_validators(
    descriptor: &ConsensusEpochDescriptor,
) -> Result<Vec<&ValidatorRecord>, ConsensusEpochError> {
    validate_network_domain(&descriptor.network_domain)?;
    validate_zone_id(&descriptor.zone_id)?;
    decode_hash32("currency_genesis_root", &descriptor.currency_genesis_root)?;
    decode_hash32("stake_snapshot_root", &descriptor.stake_snapshot_root)?;
    if descriptor.consensus_protocol_version == 0 {
        return Err(ConsensusEpochError::ZeroConsensusProtocolVersion);
    }
    if descriptor.activation_height >= descriptor.exit_height {
        return Err(ConsensusEpochError::InvalidHeightWindow);
    }
    descriptor.quorum_rule.validate()?;
    if !(MIN_VALIDATORS_PER_EPOCH..=MAX_VALIDATORS_PER_EPOCH).contains(&descriptor.validators.len())
    {
        return Err(ConsensusEpochError::ValidatorCountOutOfRange);
    }

    if !descriptor.validators.windows(2).all(|pair| {
        pair[0]
            .validator_id
            .as_bytes()
            .cmp(pair[1].validator_id.as_bytes())
            .then_with(|| {
                pair[0]
                    .public_key
                    .as_bytes()
                    .cmp(pair[1].public_key.as_bytes())
            })
            .is_lt()
    }) {
        return Err(ConsensusEpochError::NonCanonicalValidatorOrder);
    }

    let mut validator_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut control_group_weights = BTreeMap::<&str, u128>::new();
    let mut total_weight = 0u128;
    for validator in &descriptor.validators {
        validate_validator_id(&validator.validator_id)?;
        if !validator_ids.insert(validator.validator_id.as_str()) {
            return Err(ConsensusEpochError::DuplicateValidatorId(
                validator.validator_id.clone(),
            ));
        }
        validate_ed25519_public_key(&validator.public_key).map_err(|reason| {
            ConsensusEpochError::InvalidPublicKey {
                validator_id: validator.validator_id.clone(),
                reason,
            }
        })?;
        if !public_keys.insert(validator.public_key.as_str()) {
            return Err(ConsensusEpochError::DuplicatePublicKey(
                validator.public_key.clone(),
            ));
        }
        if validator.weight == 0 {
            return Err(ConsensusEpochError::ZeroWeight(
                validator.validator_id.clone(),
            ));
        }
        if validator.self_bond == 0 {
            return Err(ConsensusEpochError::ZeroSelfBond(
                validator.validator_id.clone(),
            ));
        }
        validate_control_group(&validator.control_group).map_err(|_| {
            ConsensusEpochError::InvalidControlGroup(validator.validator_id.clone())
        })?;
        let component_weight = validator
            .self_bond
            .checked_add(validator.delegated_weight)
            .ok_or_else(|| {
                ConsensusEpochError::ValidatorWeightOverflow(validator.validator_id.clone())
            })?;
        if validator.weight != component_weight {
            return Err(ConsensusEpochError::ValidatorWeightMismatch(
                validator.validator_id.clone(),
            ));
        }
        if validator.unbonding_height < descriptor.exit_height {
            return Err(ConsensusEpochError::UnbondingBeforeEpochExit(
                validator.validator_id.clone(),
            ));
        }
        total_weight = total_weight
            .checked_add(validator.weight)
            .ok_or(ConsensusEpochError::TotalWeightOverflow)?;
        let group_weight = control_group_weights
            .entry(validator.control_group.as_str())
            .or_default();
        *group_weight = group_weight
            .checked_add(validator.weight)
            .ok_or(ConsensusEpochError::ControlGroupWeightOverflow)?;
    }

    if descriptor.total_weight != total_weight {
        return Err(ConsensusEpochError::TotalWeightMismatch {
            declared: descriptor.total_weight,
            computed: total_weight,
        });
    }
    let quorum_power = quorum_power_v1(total_weight)?;
    if descriptor.quorum_power != quorum_power {
        return Err(ConsensusEpochError::QuorumPowerMismatch {
            declared: descriptor.quorum_power,
            computed: quorum_power,
        });
    }

    let maximum_fault_power = total_weight
        .checked_sub(quorum_power)
        .ok_or(ConsensusEpochError::ZeroTotalWeight)?;
    for (control_group, weight) in control_group_weights {
        if weight > maximum_fault_power {
            return Err(ConsensusEpochError::ControlGroupWeightTooHigh {
                control_group: control_group.to_owned(),
                weight,
                maximum: maximum_fault_power,
            });
        }
    }

    Ok(descriptor.validators.iter().collect())
}

fn encode_validator(validator: &ValidatorRecord) -> Result<Vec<u8>, ConsensusEpochError> {
    let public_key: [u8; 32] = hex::decode(&validator.public_key)
        .expect("validated public key is hex")
        .try_into()
        .expect("validated public key has 32 bytes");
    let mut encoded = Vec::new();
    push_field(&mut encoded, 1, validator.validator_id.as_bytes())?;
    push_field(&mut encoded, 2, &public_key)?;
    push_field(&mut encoded, 3, &validator.key_era.to_be_bytes())?;
    push_field(&mut encoded, 4, &validator.weight.to_be_bytes())?;
    push_field(&mut encoded, 5, validator.control_group.as_bytes())?;
    push_field(&mut encoded, 6, &validator.self_bond.to_be_bytes())?;
    push_field(&mut encoded, 7, &validator.delegated_weight.to_be_bytes())?;
    push_field(&mut encoded, 8, &validator.unbonding_height.to_be_bytes())?;
    Ok(encoded)
}

fn push_field(
    encoded: &mut Vec<u8>,
    field_id: u16,
    value: &[u8],
) -> Result<(), ConsensusEpochError> {
    encoded.extend_from_slice(&field_id.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| ConsensusEpochError::FieldTooLarge)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(value);
    Ok(())
}

fn validate_network_domain(value: &str) -> Result<(), ConsensusEpochError> {
    if matches!(value, RLDCOIN_MAINNET_DOMAIN | RLDCOIN_TESTNET_DOMAIN) {
        Ok(())
    } else {
        Err(ConsensusEpochError::InvalidNetworkDomain)
    }
}

fn validate_zone_id(value: &str) -> Result<(), ConsensusEpochError> {
    let Some(suffix) = value.strip_prefix("zone-") else {
        return Err(ConsensusEpochError::InvalidZoneId);
    };
    if suffix.len() == 20
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ConsensusEpochError::InvalidZoneId)
    }
}

fn validate_validator_id(value: &str) -> Result<(), ConsensusEpochError> {
    let mut bytes = value.bytes();
    let first_valid = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let rest_valid = bytes.all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
    });
    if first_valid && rest_valid && value.len() <= MAX_IDENTIFIER_BYTES {
        Ok(())
    } else {
        Err(ConsensusEpochError::InvalidValidatorId(value.to_owned()))
    }
}

fn validate_control_group(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_CONTROL_GROUP_BYTES
        || value.chars().any(char::is_control)
        || value.nfc().collect::<String>() != value
    {
        Err(())
    } else {
        Ok(())
    }
}

fn decode_hash32(field: &'static str, value: &str) -> Result<[u8; 32], ConsensusEpochError> {
    let bytes = hex::decode(value).map_err(|_| ConsensusEpochError::InvalidHash(field))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConsensusEpochError::InvalidHash(field))?;
    if hex::encode(bytes) != value {
        return Err(ConsensusEpochError::InvalidHash(field));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    fn public_key(seed: u8) -> String {
        hex::encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn validator(seed: u8, id: &str, self_bond: u128, delegated_weight: u128) -> ValidatorRecord {
        ValidatorRecord {
            validator_id: id.to_owned(),
            public_key: public_key(seed),
            key_era: 4,
            weight: self_bond + delegated_weight,
            control_group: format!("operator-{seed}"),
            self_bond,
            delegated_weight,
            unbonding_height: 50_000,
        }
    }

    fn descriptor_with(validators: Vec<ValidatorRecord>) -> ConsensusEpochDescriptor {
        let total_weight = validators.iter().map(|validator| validator.weight).sum();
        ConsensusEpochDescriptor {
            network_domain: RLDCOIN_MAINNET_DOMAIN.to_owned(),
            zone_id: "zone-0123456789abcdefabcd".to_owned(),
            currency_genesis_root: "11".repeat(32),
            protocol_era: 3,
            crypto_era: 4,
            consensus_protocol_version: 1,
            consensus_epoch: 7,
            activation_height: 1_000,
            exit_height: 2_000,
            stake_snapshot_root: "22".repeat(32),
            validators,
            total_weight,
            quorum_power: quorum_power_v1(total_weight).unwrap(),
            quorum_rule: ConsensusQuorumRule::v1(),
        }
    }

    fn descriptor() -> ConsensusEpochDescriptor {
        descriptor_with(vec![
            validator(1, "validator-a", 2, 1),
            validator(2, "validator-b", 1, 2),
            validator(3, "validator-c", 3, 0),
            validator(4, "validator-d", 2, 1),
        ])
    }

    fn refresh_totals(descriptor: &mut ConsensusEpochDescriptor) {
        descriptor.total_weight = descriptor
            .validators
            .iter()
            .map(|validator| validator.weight)
            .sum();
        descriptor.quorum_power = quorum_power_v1(descriptor.total_weight).unwrap();
    }

    fn assert_commitment_changes<F>(mutate: F)
    where
        F: FnOnce(&mut ConsensusEpochDescriptor),
    {
        let original = descriptor();
        let original_commitment = consensus_epoch_descriptor_commitment_v1(&original).unwrap();
        let mut changed = original;
        mutate(&mut changed);
        let changed_commitment = consensus_epoch_descriptor_commitment_v1(&changed).unwrap();
        assert_ne!(original_commitment, changed_commitment);
    }

    #[test]
    fn serde_round_trip_is_strict_at_every_level() {
        let expected = descriptor();
        let encoded = serde_json::to_vec(&expected).unwrap();
        assert_eq!(
            decode_consensus_epoch_descriptor_json(&encoded).unwrap(),
            expected
        );

        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["unexpected"] = json!(true);
        assert!(
            decode_consensus_epoch_descriptor_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );

        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["validators"][0]["unexpected"] = json!(true);
        assert!(
            decode_consensus_epoch_descriptor_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );

        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["quorum_rule"]["unexpected"] = json!(true);
        assert!(
            decode_consensus_epoch_descriptor_json(&serde_json::to_vec(&value).unwrap()).is_err()
        );

        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["validators"] =
            serde_json::Value::Array(vec![
                serde_json::to_value(validator(1, "validator-a", 1, 0))
                    .unwrap();
                MAX_VALIDATORS_PER_EPOCH + 1
            ]);
        let error = decode_consensus_epoch_descriptor_json(&serde_json::to_vec(&value).unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 4096"));

        assert_eq!(
            decode_consensus_epoch_descriptor_json(&vec![
                b' ';
                MAX_CONSENSUS_EPOCH_DESCRIPTOR_BYTES + 1
            ]),
            Err(ConsensusEpochError::DescriptorTooLarge)
        );
    }

    #[test]
    fn shuffled_validator_input_is_rejected_before_indexed_use() {
        let original = descriptor();
        let mut shuffled = original.clone();
        shuffled.validators.rotate_left(1);
        consensus_epoch_descriptor_commitment_v1(&original).unwrap();
        assert_eq!(
            consensus_epoch_descriptor_commitment_v1(&shuffled),
            Err(ConsensusEpochError::NonCanonicalValidatorOrder)
        );
    }

    #[test]
    fn epoch_identity_fields_change_the_commitment() {
        assert_commitment_changes(|value| value.network_domain = RLDCOIN_TESTNET_DOMAIN.to_owned());
        assert_commitment_changes(|value| value.zone_id = "zone-abcdef0123456789abcd".to_owned());
        assert_commitment_changes(|value| value.currency_genesis_root = "33".repeat(32));
        assert_commitment_changes(|value| value.protocol_era += 1);
        assert_commitment_changes(|value| value.crypto_era += 1);
        assert_commitment_changes(|value| value.consensus_protocol_version += 1);
        assert_commitment_changes(|value| value.consensus_epoch += 1);
        assert_commitment_changes(|value| value.activation_height += 1);
        assert_commitment_changes(|value| value.exit_height += 1);
        assert_commitment_changes(|value| value.stake_snapshot_root = "44".repeat(32));
    }

    #[test]
    fn every_validator_field_changes_the_commitment() {
        assert_commitment_changes(|value| value.validators[0].validator_id = "validator-aa".into());
        assert_commitment_changes(|value| value.validators[0].public_key = public_key(9));
        assert_commitment_changes(|value| value.validators[0].key_era += 1);
        assert_commitment_changes(|value| {
            value.validators[0].weight += 1;
            value.validators[0].self_bond += 1;
            refresh_totals(value);
        });
        assert_commitment_changes(|value| {
            value.validators[0].control_group = "operator-new".into()
        });
        assert_commitment_changes(|value| {
            value.validators[0].self_bond -= 1;
            value.validators[0].delegated_weight += 1;
        });
        assert_commitment_changes(|value| value.validators[0].unbonding_height += 1);
    }

    #[test]
    fn duplicate_ids_and_public_keys_are_rejected() {
        let mut duplicate_id = descriptor();
        duplicate_id.validators[1].validator_id = duplicate_id.validators[0].validator_id.clone();
        assert!(duplicate_id.validate().is_err());

        let mut duplicate_key = descriptor();
        duplicate_key.validators[1].public_key = duplicate_key.validators[0].public_key.clone();
        assert!(matches!(
            duplicate_key.validate(),
            Err(ConsensusEpochError::DuplicatePublicKey(_))
        ));
    }

    #[test]
    fn invalid_and_small_order_public_keys_are_rejected() {
        let mut malformed = descriptor();
        malformed.validators[0].public_key = "not-a-key".into();
        assert!(matches!(
            malformed.validate(),
            Err(ConsensusEpochError::InvalidPublicKey { .. })
        ));

        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        let mut weak = descriptor();
        weak.validators[0].public_key = hex::encode(identity_point);
        assert!(matches!(
            weak.validate(),
            Err(ConsensusEpochError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn zero_weight_empty_control_group_and_bad_breakdown_are_rejected() {
        let mut zero = descriptor();
        zero.validators[0].weight = 0;
        zero.validators[0].self_bond = 0;
        zero.validators[0].delegated_weight = 0;
        refresh_totals(&mut zero);
        assert!(matches!(
            zero.validate(),
            Err(ConsensusEpochError::ZeroWeight(_))
        ));

        let mut zero_bond = descriptor();
        zero_bond.validators[0].self_bond = 0;
        zero_bond.validators[0].delegated_weight = zero_bond.validators[0].weight;
        assert!(matches!(
            zero_bond.validate(),
            Err(ConsensusEpochError::ZeroSelfBond(_))
        ));

        for control_group in ["", " ", " operator", "operator\n"] {
            let mut invalid = descriptor();
            invalid.validators[0].control_group = control_group.into();
            assert!(matches!(
                invalid.validate(),
                Err(ConsensusEpochError::InvalidControlGroup(_))
            ));
        }

        let mut mismatch = descriptor();
        mismatch.validators[0].weight += 1;
        refresh_totals(&mut mismatch);
        assert!(matches!(
            mismatch.validate(),
            Err(ConsensusEpochError::ValidatorWeightMismatch(_))
        ));

        let mut overflow = descriptor();
        overflow.validators[0].weight = u128::MAX;
        overflow.validators[0].self_bond = u128::MAX;
        overflow.validators[0].delegated_weight = 1;
        overflow.total_weight = u128::MAX;
        overflow.quorum_power = quorum_power_v1(u128::MAX).unwrap();
        assert!(matches!(
            overflow.validate(),
            Err(ConsensusEpochError::ValidatorWeightOverflow(_))
        ));
    }

    #[test]
    fn total_weight_overflow_and_declared_mismatches_are_rejected() {
        let mut overflow = descriptor();
        overflow.validators[0].weight = u128::MAX;
        overflow.validators[0].self_bond = u128::MAX;
        overflow.validators[0].delegated_weight = 0;
        overflow.validators[1].weight = 1;
        overflow.validators[1].self_bond = 1;
        overflow.validators[1].delegated_weight = 0;
        overflow.total_weight = u128::MAX;
        overflow.quorum_power = quorum_power_v1(u128::MAX).unwrap();
        assert!(matches!(
            overflow.validate(),
            Err(ConsensusEpochError::TotalWeightOverflow)
        ));

        let mut total_mismatch = descriptor();
        total_mismatch.total_weight += 1;
        assert!(matches!(
            total_mismatch.validate(),
            Err(ConsensusEpochError::TotalWeightMismatch { .. })
        ));

        let mut quorum_mismatch = descriptor();
        quorum_mismatch.quorum_power -= 1;
        assert!(matches!(
            quorum_mismatch.validate(),
            Err(ConsensusEpochError::QuorumPowerMismatch { .. })
        ));
    }

    #[test]
    fn malformed_epoch_envelope_and_quorum_params_are_rejected() {
        let mut invalid = descriptor();
        invalid.network_domain = "rldcoin:unknown:v1".into();
        assert_eq!(
            invalid.validate(),
            Err(ConsensusEpochError::InvalidNetworkDomain)
        );

        let mut invalid = descriptor();
        invalid.zone_id = "ZONE-0123456789abcdefabcd".into();
        assert_eq!(invalid.validate(), Err(ConsensusEpochError::InvalidZoneId));

        let mut invalid = descriptor();
        invalid.stake_snapshot_root = "AA".repeat(32);
        assert!(matches!(
            invalid.validate(),
            Err(ConsensusEpochError::InvalidHash(_))
        ));

        let mut invalid = descriptor();
        invalid.exit_height = invalid.activation_height;
        assert_eq!(
            invalid.validate(),
            Err(ConsensusEpochError::InvalidHeightWindow)
        );

        let mut invalid = descriptor();
        invalid.validators.clear();
        invalid.total_weight = 0;
        invalid.quorum_power = 0;
        assert_eq!(
            invalid.validate(),
            Err(ConsensusEpochError::ValidatorCountOutOfRange)
        );

        let mut invalid = descriptor();
        invalid.consensus_protocol_version = 0;
        assert_eq!(
            invalid.validate(),
            Err(ConsensusEpochError::ZeroConsensusProtocolVersion)
        );

        let mut invalid = descriptor();
        invalid.quorum_rule.denominator = 4;
        assert_eq!(
            invalid.validate(),
            Err(ConsensusEpochError::UnsupportedQuorumRule)
        );
    }

    #[test]
    fn quorum_threshold_has_intersection_for_every_boundary() {
        let cases = [
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 5),
            (7, 5),
            (u128::MAX, u128::MAX - (u128::MAX - 1) / 3),
        ];
        for (total, expected) in cases {
            assert_eq!(quorum_power_v1(total).unwrap(), expected);
        }
        assert_eq!(
            quorum_power_v1(0),
            Err(ConsensusEpochError::ZeroTotalWeight)
        );

        for total in 1u128..=1_000 {
            let quorum = quorum_power_v1(total).unwrap();
            let tolerated_by_rule = (total - 1) / 3;
            let minimum_intersection = quorum - (total - quorum);
            assert!(minimum_intersection > tolerated_by_rule);
            assert!(quorum <= total);
        }
    }

    #[test]
    fn single_validator_and_overweight_control_groups_are_rejected() {
        let single = descriptor_with(vec![validator(8, "validator-max", u128::MAX, 0)]);
        assert_eq!(
            single.validate(),
            Err(ConsensusEpochError::ValidatorCountOutOfRange)
        );

        let mut captured = descriptor();
        captured.validators[1].control_group = captured.validators[0].control_group.clone();
        assert!(matches!(
            captured.validate(),
            Err(ConsensusEpochError::ControlGroupWeightTooHigh { .. })
        ));

        let mut oversized = descriptor();
        oversized.validators = vec![oversized.validators[0].clone(); MAX_VALIDATORS_PER_EPOCH + 1];
        assert_eq!(
            oversized.validate(),
            Err(ConsensusEpochError::ValidatorCountOutOfRange)
        );
    }

    #[test]
    fn parent_height_and_unbonding_window_are_enforced() {
        let descriptor = descriptor();
        descriptor
            .validate_for_parent_height(descriptor.activation_height)
            .unwrap();
        descriptor
            .validate_for_parent_height(descriptor.exit_height - 1)
            .unwrap();
        assert_eq!(
            descriptor.validate_for_parent_height(descriptor.activation_height - 1),
            Err(ConsensusEpochError::InactiveAtParentHeight)
        );
        assert_eq!(
            descriptor.validate_for_parent_height(descriptor.exit_height),
            Err(ConsensusEpochError::InactiveAtParentHeight)
        );

        let mut early_unbond = descriptor;
        early_unbond.validators[0].unbonding_height = early_unbond.exit_height - 1;
        assert!(matches!(
            early_unbond.validate(),
            Err(ConsensusEpochError::UnbondingBeforeEpochExit(_))
        ));
    }
}
