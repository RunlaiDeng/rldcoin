//! Candidate upgrade command bytes. No scheduling, migration or activation authority.
use super::v3::decimal_u128;
use crate::{hash_bytes, AdmissionContextV1, AdmissionHash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEDULE_VERSION: &str = "RLD-SCHEDULE-UPGRADE-V1";
pub const ACTIVATE_VERSION: &str = "RLD-ACTIVATE-UPGRADE-V1";
pub const SCHEDULE_SCHEMA: u16 = 0x1078;
pub const ACTIVATE_SCHEMA: u16 = 0x1079;
pub const MAX_SCHEDULE_BYTES: usize = 4096;
pub const MAX_ACTIVATE_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleUpgradeV1 {
    pub format_version: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: AdmissionHash32,
    #[serde(with = "decimal_u128")]
    pub protocol_era: u128,
    #[serde(with = "decimal_u128")]
    pub crypto_era: u128,
    #[serde(with = "decimal_u128")]
    pub sequence: u128,
    #[serde(with = "decimal_u128")]
    pub activation_height: u128,
    pub prior_active_commitment: AdmissionHash32,
    pub specification_hash: AdmissionHash32,
    pub implementation_source_commitment: AdmissionHash32,
    pub migration_id: String,
    pub migration_code_hash: AdmissionHash32,
    pub vector_root: AdmissionHash32,
    pub required_capabilities: Vec<String>,
    #[serde(deserialize_with = "required_optional_hash")]
    pub prior_finalized_upgrade: Option<AdmissionHash32>,
    pub immutable_invariant_commitment: AdmissionHash32,
}

fn required_optional_hash<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<AdmissionHash32>, D::Error> {
    Option::<AdmissionHash32>::deserialize(deserializer)
}

impl ScheduleUpgradeV1 {
    /// Parent checks are shared with the draft, but bytes and IDs are always
    /// computed from this versioned command object. No registry or finality.
    pub(crate) fn check_bootstrap_parent(&self, parent: &crate::Ledger) -> Result<u128, String> {
        self.canonical_bytes()?;
        super::upgrade_intent::UpgradeIntentDraftV1 {
            format_version: super::upgrade_intent::UPGRADE_INTENT_VERSION.into(),
            network_domain: self.network_domain.clone(),
            zone_id: self.zone_id.clone(),
            currency_genesis: self.currency_genesis,
            protocol_era: self.protocol_era,
            crypto_era: self.crypto_era,
            sequence: self.sequence,
            activation_height: self.activation_height,
            prior_active_commitment: self.prior_active_commitment,
            specification_hash: self.specification_hash,
            implementation_source_commitment: self.implementation_source_commitment,
            migration_id: self.migration_id.clone(),
            migration_code_hash: self.migration_code_hash,
            vector_root: self.vector_root,
            required_capabilities: self.required_capabilities.clone(),
            prior_finalized_upgrade: self.prior_finalized_upgrade,
            immutable_invariant_commitment: self.immutable_invariant_commitment,
        }
        .check_bootstrap_parent(parent)
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != SCHEDULE_VERSION {
            return Err("unsupported upgrade intent version".into());
        }
        AdmissionContextV1 {
            network_domain: self.network_domain.clone(),
            zone_id: self.zone_id.clone(),
            currency_genesis: self.currency_genesis,
            protocol_era: self.protocol_era,
            crypto_era: self.crypto_era,
        }
        .validate()
        .map_err(|e| e.to_string())?;
        if self.sequence == 0 || self.activation_height == 0 {
            return Err("upgrade sequence and activation height must be nonzero".into());
        }
        if (self.sequence == 1) != self.prior_finalized_upgrade.is_none()
            || self.prior_finalized_upgrade.is_some_and(|h| h.is_zero())
        {
            return Err("upgrade predecessor does not match sequence".into());
        }
        let hashes = [
            self.prior_active_commitment,
            self.specification_hash,
            self.implementation_source_commitment,
            self.migration_code_hash,
            self.vector_root,
            self.immutable_invariant_commitment,
        ];
        if hashes.iter().any(|h| h.is_zero()) {
            return Err("upgrade commitments must be nonzero".into());
        }
        fn identifier(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        }
        if !identifier(&self.migration_id)
            || self.required_capabilities.is_empty()
            || self.required_capabilities.len() > 32
            || self.required_capabilities.iter().any(|s| !identifier(s))
            || self.required_capabilities.windows(2).any(|w| w[0] >= w[1])
        {
            return Err("invalid migration identifier or noncanonical capability set".into());
        }
        if !valid_network(&self.network_domain) {
            return Err("upgrade network is not supported by the command envelope".into());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut fields = context_fields(
            &self.network_domain,
            &self.zone_id,
            self.currency_genesis,
            self.protocol_era,
            self.crypto_era,
        );
        fields.extend([
            field(10, 5, &self.sequence.to_be_bytes()),
            field(11, 5, &self.activation_height.to_be_bytes()),
            field(12, 6, &self.prior_active_commitment.0),
            field(13, 6, &self.specification_hash.0),
            field(14, 6, &self.implementation_source_commitment.0),
            field(15, 1, self.migration_id.as_bytes()),
            field(16, 6, &self.migration_code_hash.0),
            field(17, 6, &self.vector_root.0),
        ]);
        let mut capabilities = (self.required_capabilities.len() as u16)
            .to_be_bytes()
            .to_vec();
        for cap in &self.required_capabilities {
            capabilities.extend_from_slice(&(cap.len() as u16).to_be_bytes());
            capabilities.extend_from_slice(cap.as_bytes());
        }
        fields.push(field(18, 9, &capabilities));
        if let Some(previous) = self.prior_finalized_upgrade {
            fields.push(field(19, 6, &previous.0));
        }
        fields.push(field(20, 6, &self.immutable_invariant_commitment.0));
        object(SCHEDULE_SCHEMA, fields, MAX_SCHEDULE_BYTES)
    }

    pub fn from_canonical_bytes(raw: &[u8]) -> Result<Self, String> {
        let fields = parse(raw, SCHEDULE_SCHEMA, MAX_SCHEDULE_BYTES)?;
        let mut layout = vec![
            (1, 1),
            (2, 1),
            (3, 6),
            (4, 5),
            (5, 5),
            (10, 5),
            (11, 5),
            (12, 6),
            (13, 6),
            (14, 6),
            (15, 1),
            (16, 6),
            (17, 6),
            (18, 9),
        ];
        if fields.contains_key(&19) {
            layout.push((19, 6));
        }
        layout.push((20, 6));
        check_layout(&fields, &layout)?;
        let v = Self {
            format_version: SCHEDULE_VERSION.into(),
            network_domain: text(&fields, 1)?,
            zone_id: text(&fields, 2)?,
            currency_genesis: hash(&fields, 3)?,
            protocol_era: number(&fields, 4)?,
            crypto_era: number(&fields, 5)?,
            sequence: number(&fields, 10)?,
            activation_height: number(&fields, 11)?,
            prior_active_commitment: hash(&fields, 12)?,
            specification_hash: hash(&fields, 13)?,
            implementation_source_commitment: hash(&fields, 14)?,
            migration_id: text(&fields, 15)?,
            migration_code_hash: hash(&fields, 16)?,
            vector_root: hash(&fields, 17)?,
            required_capabilities: decode_capabilities(fields[&18].1)?,
            prior_finalized_upgrade: if fields.contains_key(&19) {
                Some(hash(&fields, 19)?)
            } else {
                None
            },
            immutable_invariant_commitment: hash(&fields, 20)?,
        };
        if v.canonical_bytes()? != raw {
            return Err("noncanonical schedule bytes".into());
        }
        Ok(v)
    }

    pub fn intent_id(&self) -> Result<String, String> {
        Ok(subject(&self.canonical_bytes()?))
    }
    pub fn candidate_command_bytes(&self) -> Result<Vec<u8>, String> {
        command(&self.network_domain, 37, &self.canonical_bytes()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateUpgradeV1 {
    pub format_version: String,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: AdmissionHash32,
    #[serde(with = "decimal_u128")]
    pub protocol_era: u128,
    #[serde(with = "decimal_u128")]
    pub crypto_era: u128,
    #[serde(with = "decimal_u128")]
    pub sequence: u128,
    #[serde(with = "decimal_u128")]
    pub activation_height: u128,
    pub intent_id: AdmissionHash32,
}
impl ActivateUpgradeV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.format_version != ACTIVATE_VERSION
            || !valid_network(&self.network_domain)
            || self.sequence == 0
            || self.activation_height == 0
            || self.intent_id.is_zero()
        {
            return Err("invalid upgrade activation encoding".into());
        }
        AdmissionContextV1 {
            network_domain: self.network_domain.clone(),
            zone_id: self.zone_id.clone(),
            currency_genesis: self.currency_genesis,
            protocol_era: self.protocol_era,
            crypto_era: self.crypto_era,
        }
        .validate()
        .map_err(|e| e.to_string())?;
        let mut fields = context_fields(
            &self.network_domain,
            &self.zone_id,
            self.currency_genesis,
            self.protocol_era,
            self.crypto_era,
        );
        fields.extend([
            field(10, 5, &self.sequence.to_be_bytes()),
            field(11, 5, &self.activation_height.to_be_bytes()),
            field(12, 6, &self.intent_id.0),
        ]);
        object(ACTIVATE_SCHEMA, fields, MAX_ACTIVATE_BYTES)
    }
    pub fn from_canonical_bytes(raw: &[u8]) -> Result<Self, String> {
        let f = parse(raw, ACTIVATE_SCHEMA, MAX_ACTIVATE_BYTES)?;
        check_layout(
            &f,
            &[
                (1, 1),
                (2, 1),
                (3, 6),
                (4, 5),
                (5, 5),
                (10, 5),
                (11, 5),
                (12, 6),
            ],
        )?;
        let v = Self {
            format_version: ACTIVATE_VERSION.into(),
            network_domain: text(&f, 1)?,
            zone_id: text(&f, 2)?,
            currency_genesis: hash(&f, 3)?,
            protocol_era: number(&f, 4)?,
            crypto_era: number(&f, 5)?,
            sequence: number(&f, 10)?,
            activation_height: number(&f, 11)?,
            intent_id: hash(&f, 12)?,
        };
        if v.canonical_bytes()? != raw {
            return Err("noncanonical activation bytes".into());
        }
        Ok(v)
    }
    pub fn candidate_command_bytes(&self) -> Result<Vec<u8>, String> {
        command(&self.network_domain, 38, &self.canonical_bytes()?)
    }
}

fn valid_network(network: &str) -> bool {
    matches!(network, "rldcoin:mainnet:v1" | "rldcoin:testnet:v1")
}

fn subject(raw: &[u8]) -> String {
    let mut p = crate::wire::SUBJECT_PREFIX.to_vec();
    p.extend_from_slice(raw);
    hash_bytes(&p)
}
fn command(network: &str, tag: u16, raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload = b"RLDP\0\x01\x42".to_vec();
    payload.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    payload.extend_from_slice(raw);
    crate::wire::encode_reserved_command_commitment_candidate(network, tag, &payload)
        .map_err(|e| e.to_string())
}
fn field(id: u16, kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn context_fields(
    network: &str,
    zone: &str,
    currency: AdmissionHash32,
    protocol: u128,
    crypto: u128,
) -> Vec<Vec<u8>> {
    vec![
        field(1, 1, network.as_bytes()),
        field(2, 1, zone.as_bytes()),
        field(3, 6, &currency.0),
        field(4, 5, &protocol.to_be_bytes()),
        field(5, 5, &crypto.to_be_bytes()),
    ]
}
fn object(schema: u16, fields: Vec<Vec<u8>>, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = b"RLDW\0\x01".to_vec();
    out.extend_from_slice(&schema.to_be_bytes());
    out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    for f in fields {
        out.extend(f);
    }
    if out.len() > limit {
        return Err("upgrade object exceeds byte ceiling".into());
    }
    Ok(out)
}
type Fields<'a> = BTreeMap<u16, (u8, &'a [u8])>;
fn parse(raw: &[u8], schema: u16, limit: usize) -> Result<Fields<'_>, String> {
    if raw.len() > limit
        || raw.len() < 10
        || &raw[..6] != b"RLDW\0\x01"
        || raw[6..8] != schema.to_be_bytes()
    {
        return Err("invalid upgrade wire envelope".into());
    }
    let count = u16::from_be_bytes(raw[8..10].try_into().unwrap()) as usize;
    if !matches!(
        (schema, count),
        (SCHEDULE_SCHEMA, 15 | 16) | (ACTIVATE_SCHEMA, 8)
    ) {
        return Err("invalid upgrade field count".into());
    }
    let mut remaining = &raw[10..];
    let mut fields = BTreeMap::new();
    let mut previous = 0;
    for _ in 0..count {
        if remaining.len() < 7 {
            return Err("truncated upgrade field".into());
        }
        let id = u16::from_be_bytes(remaining[..2].try_into().unwrap());
        let kind = remaining[2];
        let len = u32::from_be_bytes(remaining[3..7].try_into().unwrap()) as usize;
        remaining = &remaining[7..];
        if id <= previous || len > remaining.len() {
            return Err("unordered, duplicate or truncated upgrade field".into());
        }
        let (payload, rest) = remaining.split_at(len);
        fields.insert(id, (kind, payload));
        previous = id;
        remaining = rest;
    }
    if !remaining.is_empty() {
        return Err("trailing upgrade bytes".into());
    }
    Ok(fields)
}
fn check_layout(f: &Fields<'_>, layout: &[(u16, u8)]) -> Result<(), String> {
    if f.len() != layout.len()
        || !f
            .iter()
            .zip(layout)
            .all(|((id, (kind, _)), expected)| (*id, *kind) == *expected)
    {
        return Err("unknown or missing upgrade fields or kinds".into());
    }
    Ok(())
}
fn text(f: &Fields<'_>, id: u16) -> Result<String, String> {
    std::str::from_utf8(f[&id].1)
        .map(str::to_owned)
        .map_err(|_| "invalid UTF8 upgrade field".into())
}
fn hash(f: &Fields<'_>, id: u16) -> Result<AdmissionHash32, String> {
    Ok(AdmissionHash32(
        f[&id]
            .1
            .try_into()
            .map_err(|_| "invalid upgrade hash width")?,
    ))
}
fn number(f: &Fields<'_>, id: u16) -> Result<u128, String> {
    Ok(u128::from_be_bytes(
        f[&id]
            .1
            .try_into()
            .map_err(|_| "invalid upgrade integer width")?,
    ))
}
fn decode_capabilities(mut raw: &[u8]) -> Result<Vec<String>, String> {
    if raw.len() < 2 {
        return Err("truncated capabilities".into());
    }
    let count = u16::from_be_bytes(raw[..2].try_into().unwrap()) as usize;
    raw = &raw[2..];
    if count == 0 || count > 32 {
        return Err("capability count exceeds bound".into());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if raw.len() < 2 {
            return Err("truncated capability length".into());
        }
        let len = u16::from_be_bytes(raw[..2].try_into().unwrap()) as usize;
        raw = &raw[2..];
        if len == 0 || len > 64 || len > raw.len() {
            return Err("invalid capability length".into());
        }
        out.push(
            std::str::from_utf8(&raw[..len])
                .map_err(|_| "invalid capability UTF8")?
                .to_owned(),
        );
        raw = &raw[len..];
    }
    if !raw.is_empty() {
        return Err("trailing capabilities".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../vectors/upgrade-command-v1/vectors.json"
        ))
        .unwrap()
    }

    #[test]
    fn upgrade_commands_match_independent_codec() {
        let corpus = vectors();
        for case in corpus["positive"].as_array().unwrap() {
            let raw = hex::decode(case["wire_hex"].as_str().unwrap()).unwrap();
            let command = if case["kind"] == "schedule" {
                let value = ScheduleUpgradeV1::from_canonical_bytes(&raw).unwrap();
                assert_eq!(serde_json::to_value(&value).unwrap(), case["value"]);
                assert_eq!(value.intent_id().unwrap(), case["subject_id"]);
                assert_eq!(value.canonical_bytes().unwrap(), raw);
                value.candidate_command_bytes().unwrap()
            } else {
                let value = ActivateUpgradeV1::from_canonical_bytes(&raw).unwrap();
                assert_eq!(serde_json::to_value(&value).unwrap(), case["value"]);
                assert_eq!(value.canonical_bytes().unwrap(), raw);
                value.candidate_command_bytes().unwrap()
            };
            assert_eq!(subject(&raw), case["subject_id"]);
            assert_eq!(hex::encode(&command), case["command_hex"]);
            assert_eq!(subject(&command), case["command_hash"]);
            if case["kind"] == "schedule" {
                crate::wire::decode_wire(crate::wire::WireSchema::CommandCommitment, &command)
                    .unwrap();
                let typed: crate::ConsensusCommand = serde_json::from_value(
                    serde_json::json!({"type":"SCHEDULE_UPGRADE","payload":case["value"]}),
                )
                .unwrap();
                assert_eq!(
                    typed
                        .wire_v1_command_bytes(case["value"]["network_domain"].as_str().unwrap())
                        .unwrap(),
                    command
                );
                assert!(typed.wire_v1_command_bytes("wrong-network").is_err());
            } else {
                crate::wire::decode_wire(crate::wire::WireSchema::CommandCommitment, &command)
                    .unwrap();
                let typed = serde_json::from_value::<crate::ConsensusCommand>(
                    serde_json::json!({"type":"ACTIVATE_UPGRADE","payload":case["value"]}),
                )
                .unwrap();
                assert_eq!(
                    typed
                        .wire_v1_command_bytes(case["value"]["network_domain"].as_str().unwrap())
                        .unwrap(),
                    command
                );
                assert!(typed.wire_v1_command_bytes("wrong-network").is_err());
            }
            for end in 0..raw.len() {
                assert!(
                    if case["kind"] == "schedule" {
                        ScheduleUpgradeV1::from_canonical_bytes(&raw[..end]).is_err()
                    } else {
                        ActivateUpgradeV1::from_canonical_bytes(&raw[..end]).is_err()
                    },
                    "accepted truncated prefix {end}"
                );
            }
        }
        for case in corpus["negative"].as_array().unwrap() {
            let raw = hex::decode(case["wire_hex"].as_str().unwrap()).unwrap();
            assert!(
                if case["kind"] == "schedule" {
                    ScheduleUpgradeV1::from_canonical_bytes(&raw).is_err()
                } else {
                    ActivateUpgradeV1::from_canonical_bytes(&raw).is_err()
                },
                "accepted {}",
                case["name"]
            );
        }
    }

    #[test]
    fn upgrade_command_json_rejects_ambiguous_versions_integers_and_capabilities() {
        let corpus = vectors();
        let base = corpus["positive"][0]["value"].clone();
        let mut mutations = Vec::new();
        for key in [
            "protocol_era",
            "crypto_era",
            "sequence",
            "activation_height",
        ] {
            for value in [
                serde_json::json!(1),
                serde_json::json!("01"),
                serde_json::json!("+1"),
                serde_json::json!("340282366920938463463374607431768211456"),
            ] {
                let mut bad = base.clone();
                bad[key] = value;
                mutations.push(bad);
            }
        }
        for (key, value) in [
            (
                "format_version",
                serde_json::json!("RLD-UPGRADE-INTENT-DRAFT-V1"),
            ),
            ("sequence", serde_json::json!("0")),
            ("sequence", serde_json::json!("2")),
            ("activation_height", serde_json::json!("0")),
            ("network_domain", serde_json::json!("n".repeat(65))),
            ("zone_id", serde_json::json!("z".repeat(256))),
            ("required_capabilities", serde_json::json!(["B", "A"])),
            ("required_capabilities", serde_json::json!(["A", "A"])),
            ("required_capabilities", serde_json::json!([])),
            ("migration_code_hash", serde_json::json!("00".repeat(32))),
            ("authorized", serde_json::json!(true)),
        ] {
            let mut bad = base.clone();
            bad[key] = value;
            mutations.push(bad);
        }
        let mut missing = base.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("prior_finalized_upgrade");
        mutations.push(missing);
        for value in mutations {
            assert!(serde_json::from_value::<ScheduleUpgradeV1>(value)
                .map(|v| v.canonical_bytes().is_err())
                .unwrap_or(true));
        }
        let encoded = serde_json::to_string(&base).unwrap();
        let duplicate = format!("{{\"sequence\":\"1\",{}", &encoded[1..]);
        assert!(serde_json::from_str::<ScheduleUpgradeV1>(&duplicate).is_err());
    }
}
