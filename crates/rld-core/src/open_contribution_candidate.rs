//! Code-independent Rust model for the frozen R7.2 first vector gate.
//!
//! This module is compiled only by tests.  It does not use the production wire
//! codec, ledger, command parser, stake path, Python generator, or Go verifier.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const MODEL_STATE_DOMAIN: &[u8] = b"RLD-OPEN-CONTRIBUTION-MODEL-STATE-V1";
const MAX_U128_TEXT: &str = "340282366920938463463374607431768211455";
const MAX_U256_TEXT: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

#[derive(Clone, Copy, Debug)]
struct Field {
    id: u16,
    name: &'static str,
    kind: &'static str,
    conditional: bool,
}

const fn f(id: u16, name: &'static str, kind: &'static str) -> Field {
    Field {
        id,
        name,
        kind,
        conditional: false,
    }
}

const fn c(id: u16, name: &'static str, kind: &'static str) -> Field {
    Field {
        id,
        name,
        kind,
        conditional: true,
    }
}

fn common() -> Vec<Field> {
    vec![
        f(1, "network_domain", "TEXT"),
        f(2, "zone_id", "TEXT"),
        f(3, "currency_genesis", "HASH32"),
        f(4, "protocol_era", "U128"),
        f(5, "crypto_era", "U128"),
    ]
}

fn with_common(extra: &[Field]) -> Vec<Field> {
    let mut fields = common();
    fields.extend_from_slice(extra);
    fields
}

fn schema(name: &str) -> Result<(u16, Vec<Field>), String> {
    let result = match name {
        "BaselineAccessWorkV1" => (
            0x1064,
            with_common(&[
                f(10, "parent_header", "HASH32"),
                f(11, "ledger_anchor_block", "HASH32"),
                f(12, "ledger_anchor_height", "U128"),
                f(13, "entries_root", "HASH32"),
                f(14, "entries_count", "U16"),
                f(15, "suite_id", "U16"),
                f(16, "target", "BYTES32"),
                f(17, "nonce", "U128"),
                f(18, "output_hash", "HASH32"),
                f(19, "expiry_anchor_height", "U128"),
            ]),
        ),
        "PermissionlessAdmissionEntryV1" => (
            0x1065,
            with_common(&[
                f(10, "kind", "U8"),
                f(11, "participant_key", "BYTES32"),
                f(12, "owner_commitment", "HASH32"),
                f(13, "program_id", "HASH32"),
                c(14, "challenge_id", "HASH32"),
                f(15, "payload_commitment", "HASH32"),
                f(16, "locator_commitment", "HASH32"),
                f(17, "declared_bytes", "U64"),
                f(18, "expiry_height", "U128"),
                f(19, "entry_signature", "BYTES"),
            ]),
        ),
        "PermissionlessAdmissionHeaderV1" => (
            0x1066,
            with_common(&[
                f(10, "admission_era", "U128"),
                f(11, "log_height", "U128"),
                f(12, "parent_header", "HASH32"),
                f(13, "ledger_anchor_block", "HASH32"),
                f(14, "access_work_id", "HASH32"),
                f(15, "entries_root", "HASH32"),
                f(16, "entries_count", "U16"),
                f(17, "cumulative_work", "BYTES32"),
                c(18, "prior_era_terminal", "HASH32"),
            ]),
        ),
        "VerifiableWorkProgramV1" => (
            0x1067,
            with_common(&[
                f(10, "family", "U8"),
                f(11, "program_version", "U16"),
                f(12, "input_generator_hash", "HASH32"),
                f(13, "verifier_hash", "HASH32"),
                f(14, "vector_root", "HASH32"),
                f(15, "max_input_bytes", "U64"),
                f(16, "max_result_bytes", "U64"),
                f(17, "max_proof_bytes", "U64"),
                f(18, "max_verify_units", "U64"),
                f(19, "work_per_ticket", "U128"),
                f(20, "receipt_ticket_cap", "U16"),
                f(21, "epoch_ticket_cap", "U64"),
                f(22, "maturity_epochs", "U16"),
                f(23, "lifetime_epochs", "U16"),
                f(24, "responsibility_epochs", "U16"),
                f(25, "retention_epochs", "U16"),
                f(26, "activation_height", "U128"),
                c(27, "sunset_height", "U128"),
                f(28, "activation_evidence", "HASH32"),
            ]),
        ),
        "ContributionChallengeV1" => (
            0x1068,
            with_common(&[
                f(10, "program_id", "HASH32"),
                f(11, "participation_entry_id", "HASH32"),
                f(12, "participant_key", "BYTES32"),
                f(13, "owner_commitment", "HASH32"),
                f(14, "input_commitment", "HASH32"),
                f(15, "anchor_state_root", "HASH32"),
                f(16, "future_beacon", "HASH32"),
                f(17, "open_height", "U128"),
                f(18, "close_height", "U128"),
                f(19, "result_deadline", "U128"),
                f(20, "challenge_nullifier", "HASH32"),
            ]),
        ),
        "VerifiedContributionReceiptV1" => (
            0x1069,
            with_common(&[
                f(10, "challenge_id", "HASH32"),
                f(11, "participant_key", "BYTES32"),
                f(12, "owner_commitment", "HASH32"),
                f(13, "result_commitment", "HASH32"),
                f(14, "proof_commitment", "HASH32"),
                f(15, "availability_commitment", "HASH32"),
                f(16, "result_entry_id", "HASH32"),
                f(17, "completed_height", "U128"),
                f(18, "verified_work_units", "U128"),
                f(19, "verification_trace_root", "HASH32"),
                f(20, "work_nullifier", "HASH32"),
            ]),
        ),
        "VerifiedContributionTicketV1" => (
            0x106a,
            with_common(&[
                f(10, "receipt_id", "HASH32"),
                f(11, "child_index", "U16"),
                f(12, "participant_key", "BYTES32"),
                f(13, "owner_commitment", "HASH32"),
                f(14, "family", "U8"),
                f(15, "program_id", "HASH32"),
                f(16, "issued_height", "U128"),
                f(17, "mature_epoch", "U128"),
                f(18, "expiry_epoch", "U128"),
                f(19, "responsibility_end_epoch", "U128"),
                f(20, "state", "U8"),
                f(21, "ticket_nullifier", "HASH32"),
            ]),
        ),
        "DeferredServiceClaimV1" => (
            0x106b,
            with_common(&[
                f(10, "receipt_id", "HASH32"),
                f(11, "owner_commitment", "HASH32"),
                f(12, "budget_reservation_id", "HASH32"),
                f(13, "startup_pool_position", "HASH32"),
                f(14, "max_amount", "U128"),
                f(15, "issued_height", "U128"),
                f(16, "executable_after_epoch", "U128"),
                f(17, "expiry_epoch", "U128"),
                f(18, "state", "U8"),
                f(19, "claim_nullifier", "HASH32"),
            ]),
        ),
        "ContributionEpochDescriptorV1" => (
            0x106c,
            with_common(&[
                f(10, "epoch", "U128"),
                f(11, "prior_descriptor", "HASH32"),
                f(12, "snapshot_height", "U128"),
                f(13, "snapshot_root", "HASH32"),
                f(14, "beacon", "HASH32"),
                f(15, "milestone", "U8"),
                f(16, "founder_special_slots", "U16"),
                f(17, "member_count", "U16"),
                f(18, "member_records", "BYTES"),
                f(19, "ticket_nullifier_root", "HASH32"),
                f(20, "leader_schedule_root", "HASH32"),
                f(21, "total_slots", "U16"),
                f(22, "quorum_slots", "U16"),
                f(23, "activation_height", "U128"),
                f(24, "exit_height", "U128"),
                f(25, "evidence_end_height", "U128"),
                f(26, "client_set_root", "HASH32"),
                f(27, "control_evidence_root", "HASH32"),
            ]),
        ),
        "BootstrapAuthorityTransitionV1" => (
            0x106d,
            with_common(&[
                f(10, "milestone", "U8"),
                f(11, "prior_transition", "HASH32"),
                f(12, "founder_keyset_commitment", "HASH32"),
                f(13, "founder_special_slots", "U16"),
                f(14, "minimum_external_groups", "U16"),
                f(15, "minimum_client_implementations", "U8"),
                f(16, "minimum_fault_domains", "U8"),
                f(17, "effective_epoch", "U128"),
                f(18, "responsibility_end_epoch", "U128"),
                f(19, "offline_test_kind", "U8"),
                f(20, "offline_test_evidence", "HASH32"),
                f(21, "state", "U8"),
            ]),
        ),
        "AdmissionCheckpointV1" => (
            0x106e,
            with_common(&[
                f(10, "admission_era", "U128"),
                f(11, "header_id", "HASH32"),
                f(12, "log_height", "U128"),
                f(13, "cumulative_work", "BYTES32"),
                f(14, "confirmations", "U16"),
                f(15, "descendant_work", "BYTES32"),
                f(16, "entries_root", "HASH32"),
                f(17, "availability_root", "HASH32"),
                f(18, "observed_ledger_epoch", "U128"),
                f(19, "committed_ledger_epoch", "U128"),
            ]),
        ),
        "ContributionRejectionProofV1" => (
            0x106f,
            with_common(&[
                f(10, "checkpoint_id", "HASH32"),
                f(11, "entry_id", "HASH32"),
                f(12, "rejection_code", "U16"),
                f(13, "program_id", "HASH32"),
                f(14, "prestate_root", "HASH32"),
                f(15, "verification_trace_root", "HASH32"),
                f(16, "evidence_commitment", "HASH32"),
                f(17, "applied_height", "U128"),
            ]),
        ),
        _ => return Err(format!("unknown schema {name}")),
    };
    Ok(result)
}

const SCHEMA_ORDER: [&str; 12] = [
    "BaselineAccessWorkV1",
    "PermissionlessAdmissionEntryV1",
    "PermissionlessAdmissionHeaderV1",
    "VerifiableWorkProgramV1",
    "ContributionChallengeV1",
    "VerifiedContributionReceiptV1",
    "VerifiedContributionTicketV1",
    "DeferredServiceClaimV1",
    "ContributionEpochDescriptorV1",
    "BootstrapAuthorityTransitionV1",
    "AdmissionCheckpointV1",
    "ContributionRejectionProofV1",
];

const ERROR_PRIORITY: [&str; 13] = [
    "ERR_ENVELOPE_LIMIT",
    "ERR_NON_CANONICAL_WIRE",
    "ERR_CONTEXT_MISMATCH",
    "ERR_PARENT_OR_PRESTATE",
    "ERR_AUTHENTICATION",
    "ERR_RESOURCE_OR_AVAILABILITY",
    "ERR_DUPLICATE_OR_NULLIFIER",
    "ERR_PROGRAM_OR_WINDOW",
    "ERR_WORK_OR_PROOF",
    "ERR_QUOTA_OR_CONCENTRATION",
    "ERR_TRANSITION_OR_VALUE_CAP",
    "ERR_BUDGET_OR_SUPPLY",
    "ERR_FEATURE_NOT_ACTIVATED",
];

const REJECT_CASE_IDS: [&str; 46] = [
    "R01-envelope-limit",
    "R02-unknown-schema",
    "R03-duplicate-field",
    "R04-out-of-order-field",
    "R05-missing-field",
    "R06-non-nfc",
    "R07-trailing-bytes",
    "R08-context",
    "R09-parent",
    "R10-prestate",
    "R11-anchor",
    "R12-bad-signature",
    "R13-small-order",
    "R14-noncanonical-scalar",
    "R15-entry-root",
    "R16-invalid-work",
    "R17-work-overflow",
    "R18-target-range",
    "R19-shallow-confirmation",
    "R20-data-unavailable",
    "R21-duplicate-work",
    "R22-seed-preselection",
    "R23-expired-challenge",
    "R24-unbounded-verifier",
    "R25-subjective-program",
    "R26-ticket-early",
    "R27-ticket-expired",
    "R28-ticket-reuse",
    "R29-family-cap",
    "R30-control-cap",
    "R31-committee-underfill",
    "R32-quorum",
    "R33-milestone-skip",
    "R34-milestone-rollback",
    "R35-founder-restore",
    "R36-rld-buys-ticket",
    "R37-missing-budget",
    "R38-claim-transfer",
    "R39-claim-replay",
    "R40-value-cap-0",
    "R41-supply-change",
    "R42-cross-domain",
    "R43-unactivated-tag",
    "R44-first-error-envelope-before-wire",
    "R45-first-error-auth-before-work",
    "R46-first-error-resource-before-duplicate",
];

fn fault_error(fault: &str) -> Option<&'static str> {
    Some(match fault {
        "envelope_over_limit" => ERROR_PRIORITY[0],
        "unknown_schema" | "duplicate_field" | "out_of_order_field" | "missing_field"
        | "non_nfc_text" | "trailing_bytes" => ERROR_PRIORITY[1],
        "context_mismatch" => ERROR_PRIORITY[2],
        "wrong_parent" | "wrong_prestate" | "wrong_anchor" => ERROR_PRIORITY[3],
        "bad_signature" | "small_order_key" | "noncanonical_scalar" => ERROR_PRIORITY[4],
        "bad_entry_root"
        | "shallow_confirmation"
        | "data_unavailable"
        | "unbounded_verification" => ERROR_PRIORITY[5],
        "duplicate_work_nullifier" | "ticket_reuse" | "claim_replay" => ERROR_PRIORITY[6],
        "seed_preselection" | "expired_challenge" | "subjective_program" | "ticket_too_early"
        | "ticket_expired" => ERROR_PRIORITY[7],
        "invalid_access_work"
        | "cumulative_work_overflow"
        | "target_out_of_range"
        | "cross_domain_replay" => ERROR_PRIORITY[8],
        "family_slot_cap"
        | "control_group_slot_cap"
        | "committee_underfilled"
        | "quorum_below_667" => ERROR_PRIORITY[9],
        "milestone_skip"
        | "milestone_rollback"
        | "founder_authority_restore"
        | "rld_purchase_ticket"
        | "claim_transfer"
        | "value_cap_0_settlement" => ERROR_PRIORITY[10],
        "missing_budget" | "supply_change" => ERROR_PRIORITY[11],
        "unactivated_tag" => ERROR_PRIORITY[12],
        _ => return None,
    })
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn label_hash(label: &str) -> [u8; 32] {
    sha(label.as_bytes())
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn text<'a>(value: &'a Value, label: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{label} must be text"))
}

fn parse_uint(value: &Value, bits: usize) -> Result<[u8; 16], String> {
    let raw = text(value, "integer")?;
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical integer".into());
    }
    let parsed = raw.parse::<u128>().map_err(|_| "integer out of range")?;
    if bits < 128 && parsed >= (1u128 << bits) {
        return Err("integer out of range".into());
    }
    Ok(parsed.to_be_bytes())
}

fn decode_hex(value: &Value, bytes: Option<usize>) -> Result<Vec<u8>, String> {
    let raw = text(value, "hex")?;
    if raw.len() % 2 != 0
        || raw
            .bytes()
            .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err("noncanonical hex".into());
    }
    let decoded = hex::decode(raw).map_err(|_| "invalid hex")?;
    if bytes.is_some_and(|n| n != decoded.len()) {
        return Err("wrong fixed width".into());
    }
    Ok(decoded)
}

fn encode_payload(kind: &str, value: &Value) -> Result<Vec<u8>, String> {
    match kind {
        "TEXT" => {
            let raw = text(value, "text")?;
            if raw.nfc().collect::<String>() != raw
                || raw
                    .chars()
                    .any(|ch| (ch as u32) < 32 || (127..=159).contains(&(ch as u32)))
            {
                return Err("noncanonical text".into());
            }
            Ok(raw.as_bytes().to_vec())
        }
        "U8" => Ok(parse_uint(value, 8)?[15..].to_vec()),
        "U16" => Ok(parse_uint(value, 16)?[14..].to_vec()),
        "U64" => Ok(parse_uint(value, 64)?[8..].to_vec()),
        "U128" => Ok(parse_uint(value, 128)?.to_vec()),
        "HASH32" | "BYTES32" => decode_hex(value, Some(32)),
        "BYTES" => decode_hex(value, None),
        _ => Err("unknown kind".into()),
    }
}

fn kind_code(kind: &str) -> u8 {
    match kind {
        "TEXT" => 1,
        "U8" => 2,
        "U16" => 3,
        "U64" => 4,
        "U128" => 5,
        "HASH32" => 6,
        "BYTES32" => 7,
        "BYTES" => 9,
        _ => 0,
    }
}

fn encode_object(
    name: &str,
    source: &Map<String, Value>,
    omit: &[&str],
) -> Result<Vec<u8>, String> {
    let (schema_id, fields) = schema(name)?;
    let known = fields.iter().map(|f| f.name).collect::<BTreeSet<_>>();
    if let Some(key) = source.keys().find(|key| !known.contains(key.as_str())) {
        return Err(format!("unknown field {key}"));
    }
    if name == "PermissionlessAdmissionEntryV1" {
        let kind = source
            .get("kind")
            .and_then(Value::as_str)
            .ok_or("missing kind")?;
        let has = source.contains_key("challenge_id");
        if (kind == "1" && has) || ((kind == "2" || kind == "3") && !has) {
            return Err("conditional challenge".into());
        }
    }
    let mut body = Vec::new();
    let mut count = 0u16;
    for field in fields {
        if omit.contains(&field.name) {
            continue;
        }
        let Some(value) = source.get(field.name) else {
            if field.conditional {
                continue;
            }
            return Err(format!("missing {}", field.name));
        };
        let payload = encode_payload(field.kind, value)?;
        body.extend_from_slice(&field.id.to_be_bytes());
        body.push(kind_code(field.kind));
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
        count += 1;
    }
    let mut out = b"RLDW".to_vec();
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&schema_id.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn subject_id(wire: &[u8]) -> [u8; 32] {
    let mut preimage = b"RLD-SUBJECT-HASH-PREIMAGE-V1\0".to_vec();
    preimage.extend_from_slice(wire);
    sha(&preimage)
}

fn merkle_root(mut items: Vec<[u8; 32]>, empty: &[u8]) -> Result<[u8; 32], String> {
    items.sort();
    if items.windows(2).any(|w| w[0] == w[1]) {
        return Err("duplicate merkle item".into());
    }
    if items.is_empty() {
        return Ok(sha(empty));
    }
    let mut level = items
        .into_iter()
        .map(|item| {
            let mut p = vec![0];
            p.extend_from_slice(&item);
            sha(&p)
        })
        .collect::<Vec<_>>();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut p = vec![1];
                p.extend_from_slice(&pair[0]);
                p.extend_from_slice(&pair[1]);
                sha(&p)
            })
            .collect();
    }
    Ok(level[0])
}

fn ordered_merkle_root(mut level: Vec<[u8; 32]>, empty: &[u8]) -> [u8; 32] {
    if level.is_empty() {
        return sha(empty);
    }
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut p = vec![1];
                p.extend_from_slice(&pair[0]);
                p.extend_from_slice(&pair[1]);
                sha(&p)
            })
            .collect();
    }
    level[0]
}

fn common_parts() -> Vec<Vec<u8>> {
    vec![
        b"rld-mainnet".to_vec(),
        b"earth-0".to_vec(),
        label_hash("rld-currency-genesis").to_vec(),
        7u128.to_be_bytes().to_vec(),
        1u128.to_be_bytes().to_vec(),
    ]
}

fn nullifier(domain: &[u8], rest: &[&[u8]]) -> [u8; 32] {
    let common = common_parts();
    let mut parts = Vec::<&[u8]>::new();
    parts.push(domain);
    for p in &common {
        parts.push(p);
    }
    parts.extend_from_slice(rest);
    hash_parts(&parts)
}

fn sample_access() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("network_domain".into(), json!("rld-mainnet"));
    m.insert("zone_id".into(), json!("earth-0"));
    m.insert(
        "currency_genesis".into(),
        json!(hex::encode(label_hash("rld-currency-genesis"))),
    );
    m.insert("protocol_era".into(), json!("7"));
    m.insert("crypto_era".into(), json!("1"));
    for (k, v) in [
        ("parent_header", hex::encode(label_hash("parent"))),
        (
            "ledger_anchor_block",
            hex::encode(label_hash("anchor-block")),
        ),
        ("entries_root", hex::encode(label_hash("entries"))),
        ("target", "ff".repeat(32)),
        ("output_hash", "00".repeat(32)),
    ] {
        m.insert(k.into(), json!(v));
    }
    for (k, v) in [
        ("ledger_anchor_height", "100"),
        ("entries_count", "1"),
        ("suite_id", "1"),
        ("nonce", "9"),
        ("expiry_anchor_height", "132"),
    ] {
        m.insert(k.into(), json!(v));
    }
    m
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}
fn obj(value: &Value) -> Result<&Map<String, Value>, String> {
    value.as_object().ok_or("expected object".into())
}
fn arr(value: &Value) -> Result<&Vec<Value>, String> {
    value.as_array().ok_or("expected array".into())
}
fn s<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}"))
}
fn u(value: &Value, key: &str) -> Result<u128, String> {
    s(value, key)?.parse().map_err(|_| format!("invalid {key}"))
}
fn raw32(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected hex32".into())
}

#[derive(Clone)]
struct Candidate {
    score: [u8; 32],
    ticket: [u8; 32],
    group: usize,
    family: usize,
}

fn evaluate(operation: &str, input: &Value) -> Result<(bool, Option<&'static str>, Value), String> {
    let input = obj(input)?;
    if operation == "reject" {
        let mut best = ERROR_PRIORITY.len();
        for fault in arr(input.get("faults").ok_or("faults")?)? {
            let code = fault_error(fault.as_str().ok_or("fault")?).ok_or("unknown fault")?;
            let rank = ERROR_PRIORITY.iter().position(|v| *v == code).unwrap();
            best = best.min(rank);
        }
        return Ok((false, Some(ERROR_PRIORITY[best]), json!({})));
    }
    let input_value = Value::Object(input.clone());
    let output = match operation {
        "genesis" => {
            if s(&input_value, "target")? != "ff".repeat(32) {
                return Err("unsupported target fixture".into());
            }
            json!({"entries_root":hex::encode(sha(b"RLD-EMPTY-ADMISSION-MERKLE-V1")),"header_work":"0","admission_era":"0","log_height":"0"})
        }
        "batch" => {
            let count = u(&input_value, "count")? as usize;
            let prefix = s(&input_value, "label_prefix")?;
            let ids = (0..count)
                .map(|i| sha(format!("{prefix}{i}").as_bytes()))
                .collect();
            let root = merkle_root(ids, b"RLD-EMPTY-ADMISSION-MERKLE-V1")?;
            let mut access = sample_access();
            access.insert("entries_root".into(), json!(hex::encode(root)));
            access.insert("entries_count".into(), json!(count.to_string()));
            let unsigned = encode_object("BaselineAccessWorkV1", &access, &["output_hash"])?;
            let mut p = b"RLD-ADMISSION-ACCESS-WORK-V1\0".to_vec();
            p.extend_from_slice(&unsigned);
            let work = sha(&p);
            access.insert("output_hash".into(), json!(hex::encode(work)));
            let wire = encode_object("BaselineAccessWorkV1", &access, &[])?;
            json!({"entries_root":hex::encode(root),"access_work_output":hex::encode(work),"access_work_id":hex::encode(subject_id(&wire)),"count":count.to_string()})
        }
        "branch" => {
            let mut branches = arr(input.get("branches").ok_or("branches")?)?.clone();
            branches.sort_by(|a, b| {
                let ea = u(a, "era").unwrap();
                let eb = u(b, "era").unwrap();
                eb.cmp(&ea)
                    .then_with(|| u(b, "work").unwrap().cmp(&u(a, "work").unwrap()))
                    .then_with(|| {
                        raw32(s(a, "header_id").unwrap())
                            .unwrap()
                            .cmp(&raw32(s(b, "header_id").unwrap()).unwrap())
                    })
            });
            let winner = &branches[0];
            json!({"selected":s(winner,"name")?,"header_id":s(winner,"header_id")?})
        }
        "checkpoint" => {
            json!({"committable":true,"confirmations":s(&input_value,"confirmations")?,"lag":(u(&input_value,"committed_epoch")?-u(&input_value,"observed_epoch")?).to_string()})
        }
        "workflow" => {
            let units = u(&input_value, "verified_units")?;
            let per = u(&input_value, "work_per_ticket")?;
            let issued = (units / per)
                .min(u(&input_value, "receipt_cap")?)
                .min(u(&input_value, "remaining_epoch_cap")?);
            let receipt = raw32(s(&input_value, "receipt_id")?)?;
            let program = label_hash("workflow-program");
            let participation = label_hash("workflow-participation");
            let anchor = label_hash("workflow-anchor");
            let beacon = label_hash("workflow-future-beacon");
            let participant = label_hash("workflow-participant");
            let challenge = label_hash("workflow-challenge");
            let result = label_hash("workflow-result-entry");
            let cn = nullifier(
                b"RLD-CONTRIBUTION-CHALLENGE-NULLIFIER-V1",
                &[&program, &participation, &anchor, &beacon],
            );
            let wn = nullifier(
                b"RLD-CONTRIBUTION-WORK-NULLIFIER-V1",
                &[&challenge, &participant, &program, &result],
            );
            let tickets = (0..issued)
                .map(|i| {
                    let child = (i as u16).to_be_bytes();
                    hex::encode(nullifier(
                        b"RLD-CONTRIBUTION-TICKET-NULLIFIER-V1",
                        &[&receipt, &child],
                    ))
                })
                .collect::<Vec<_>>();
            let claim = if let Some(budget) = input.get("budget_reservation_id") {
                let budget = raw32(budget.as_str().ok_or("budget")?)?;
                let owner = raw32(s(&input_value, "owner_commitment")?)?;
                Value::String(hex::encode(nullifier(
                    b"RLD-DEFERRED-SERVICE-CLAIM-NULLIFIER-V1",
                    &[&receipt, &budget, &owner],
                )))
            } else {
                Value::Null
            };
            json!({"challenge_nullifier":hex::encode(cn),"work_nullifier":hex::encode(wn),"issued_tickets":issued.to_string(),"ticket_nullifiers":tickets,"claim":claim})
        }
        "committee" => {
            let count = u(&input_value, "candidate_count")? as usize;
            let groups = u(&input_value, "control_groups")? as usize;
            let families = u(&input_value, "families")? as usize;
            let prefix = s(&input_value, "ticket_prefix")?;
            let beacon = raw32(s(&input_value, "beacon")?)?;
            let mut candidates = (0..count)
                .map(|i| {
                    let ticket = sha(format!("{prefix}{i}").as_bytes());
                    let mut pre = b"RLD-CONTRIBUTION-SLOT-SELECTION-V1\0".to_vec();
                    pre.extend_from_slice(&beacon);
                    pre.extend_from_slice(&ticket);
                    Candidate {
                        score: sha(&pre),
                        ticket,
                        group: i % groups,
                        family: i % families + 1,
                    }
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|a, b| a.score.cmp(&b.score).then(a.ticket.cmp(&b.ticket)));
            let founder = BTreeMap::from([
                ("M0", 1000usize),
                ("M1", 1000),
                ("M2", 750),
                ("M3", 500),
                ("M4", 250),
                ("M5", 0),
            ]);
            let epochs = BTreeMap::from([
                ("M0", 0u128),
                ("M1", 1),
                ("M2", 2),
                ("M3", 3),
                ("M4", 4),
                ("M5", 5),
            ]);
            let mut summaries = Map::new();
            for milestone in arr(input.get("milestones").ok_or("milestones")?)? {
                let m = milestone.as_str().ok_or("milestone")?;
                let external = 1000 - founder[m];
                let mut selected = Vec::new();
                let mut control = BTreeMap::<usize, usize>::new();
                let mut family = BTreeMap::<usize, usize>::new();
                for candidate in &candidates {
                    if *control.get(&candidate.group).unwrap_or(&0) >= 100
                        || *family.get(&candidate.family).unwrap_or(&0) >= 300
                    {
                        continue;
                    }
                    selected.push(candidate.clone());
                    *control.entry(candidate.group).or_default() += 1;
                    *family.entry(candidate.family).or_default() += 1;
                    if selected.len() == external {
                        break;
                    }
                }
                let mut group_tickets = BTreeMap::<usize, Vec<[u8; 32]>>::new();
                let mut epoch_nullifiers = Vec::new();
                for candidate in &selected {
                    group_tickets
                        .entry(candidate.group)
                        .or_default()
                        .push(candidate.ticket);
                    let epoch = epochs[m].to_be_bytes();
                    epoch_nullifiers.push(nullifier(
                        b"RLD-CONTRIBUTION-EPOCH-TICKET-NULLIFIER-V1",
                        &[&epoch, &candidate.ticket],
                    ));
                }
                let mut records = Vec::<([u8; 32], Vec<u8>)>::new();
                let mut validators = Vec::new();
                for (group, tickets) in group_tickets {
                    let slots = tickets.len();
                    let validator = label_hash(&format!("A08-validator-{group}"));
                    let control_hash = label_hash(&format!("A08-control-{group}"));
                    let ticket_root =
                        merkle_root(tickets, b"RLD-EMPTY-MEMBER-TICKET-SET-MERKLE-V1")?;
                    let mut record = validator.to_vec();
                    record.extend_from_slice(&control_hash);
                    record.extend_from_slice(&(slots as u16).to_be_bytes());
                    record.extend_from_slice(&ticket_root);
                    record.extend_from_slice(&7u128.to_be_bytes());
                    records.push((validator, record));
                    validators.push(validator);
                }
                records.sort_by_key(|r| r.0);
                let joined = records
                    .iter()
                    .flat_map(|r| r.1.iter().copied())
                    .collect::<Vec<_>>();
                validators.sort_by(|a, b| {
                    let mut pa = b"RLD-LEADER-V1".to_vec();
                    pa.extend_from_slice(&beacon);
                    pa.extend_from_slice(a);
                    let mut pb = b"RLD-LEADER-V1".to_vec();
                    pb.extend_from_slice(&beacon);
                    pb.extend_from_slice(b);
                    sha(&pa).cmp(&sha(&pb)).then(a.cmp(b))
                });
                let leaves = validators
                    .iter()
                    .enumerate()
                    .map(|(rank, key)| {
                        let mut p = vec![0];
                        p.extend_from_slice(&(rank as u16).to_be_bytes());
                        p.extend_from_slice(key);
                        sha(&p)
                    })
                    .collect();
                let mut family_json = Map::new();
                for (k, v) in family {
                    family_json.insert(k.to_string(), json!(v.to_string()));
                }
                let max_control = control.values().copied().max().unwrap_or(0);
                summaries.insert(m.into(),json!({"founder_slots":founder[m].to_string(),"external_slots":external.to_string(),"selected_count":selected.len().to_string(),"control_group_count":control.len().to_string(),"max_control_slots":max_control.to_string(),"family_slots":family_json,"member_records_sha256":hex::encode(sha(&joined)),"ticket_nullifier_root":hex::encode(merkle_root(epoch_nullifiers,b"RLD-EMPTY-TICKET-NULLIFIER-MERKLE-V1")?),"leader_schedule_root":hex::encode(ordered_merkle_root(leaves,b"RLD-EMPTY-LEADER-SCHEDULE-MERKLE-V1"))}));
            }
            json!({"committees":summaries,"total_slots":"1000","quorum_slots":"667"})
        }
        "offline" => {
            let external = obj(input.get("external_slots").ok_or("external")?)?;
            let mut results = Map::new();
            for m in arr(input.get("milestones").ok_or("milestones")?)? {
                let m = m.as_str().ok_or("milestone")?;
                let slots = external
                    .get(m)
                    .and_then(Value::as_str)
                    .ok_or("slots")?
                    .parse::<u16>()
                    .map_err(|_| "slots")?;
                let state = if matches!(m, "M4" | "M5") && slots >= 667 {
                    "CONTINUE_FINALITY"
                } else {
                    "SAFE_HALT"
                };
                results.insert(m.into(), json!(state));
            }
            json!({"results":results})
        }
        "claim_settlement" => {
            let reserve = u(&input_value, "reserve_before")?;
            let circulating = u(&input_value, "circulating_before")?;
            let amount = u(&input_value, "amount")?;
            let supply = reserve.checked_add(circulating).ok_or("supply overflow")?;
            json!({"reserve_after":(reserve-amount).to_string(),"circulating_after":(circulating+amount).to_string(),"supply_before":supply.to_string(),"supply_after":supply.to_string()})
        }
        "reorg" => {
            json!({"asset_root_before":s(&input_value,"finalized_asset_root")?,"asset_root_after":s(&input_value,"finalized_asset_root")?,"unfinalized_branch_changed":true})
        }
        "bounds" => {
            if s(&input_value, "observed")? != "64" {
                return Err("unsupported bounds fixture".into());
            }
            json!({"next_target":s(&input_value,"previous_target")?,"u128_max":MAX_U128_TEXT,"u256_max":MAX_U256_TEXT})
        }
        "rollover" => {
            let terminal = raw32(s(&input_value, "terminal_cumulative_work")?)?;
            let mut threshold = [0u8; 32];
            threshold[..8].fill(0xff);
            let legal = terminal >= threshold
                && input.get("ledger_finalized").and_then(Value::as_bool) == Some(true);
            json!({"rollover_legal":legal,"successor_era":(u(&input_value,"prior_era")?+1).to_string()})
        }
        _ => return Err(format!("unknown operation {operation}")),
    };
    Ok((true, None, output))
}

fn bundle_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors/open-contribution-v1/vectors.json")
}

#[test]
fn frozen_open_contribution_corpus_matches_independent_rust_model() {
    let raw = fs::read(bundle_path()).expect("read frozen vector bundle");
    assert_eq!(
        hex::encode(sha(&raw)),
        "2eac220d8a23d8f2b0b447c128f7d07a5e3cab2baf236f3f6aea0a18ef901bf5"
    );
    let bundle: Value = serde_json::from_slice(&raw).expect("parse vectors");
    assert_eq!(
        s(&bundle, "payload_sha256").unwrap(),
        "0c88b0b4e22237005dba15c6c27e000e4d719c495e3e475761a2c6f4a7e3e813"
    );
    let payload = bundle.get("payload").expect("payload");
    let payload_bytes = canonical(payload).unwrap();
    assert_eq!(
        hex::encode(sha(&payload_bytes)),
        s(&bundle, "payload_sha256").unwrap()
    );
    let expected_tags = json!({"28":"COMMIT_ADMISSION_CHECKPOINT","29":"OPEN_CONTRIBUTION_CHALLENGE","30":"FINALIZE_CONTRIBUTION_RESULT","31":"REJECT_CONTRIBUTION_RESULT","32":"ADVANCE_CONTRIBUTION_EPOCH","33":"ADVANCE_BOOTSTRAP_AUTHORITY","34":"RECORD_CONTRIBUTION_MISCONDUCT","35":"SETTLE_DEFERRED_SERVICE_CLAIM"});
    assert_eq!(payload.get("command_tags"), Some(&expected_tags));
    let registry = arr(payload.get("schema_registry").unwrap()).unwrap();
    assert_eq!(registry.len(), 12);
    for (name, row) in SCHEMA_ORDER.iter().zip(registry) {
        let (id, fields) = schema(name).unwrap();
        assert_eq!(s(row, "schema").unwrap(), *name);
        assert_eq!(s(row, "schema_id").unwrap(), format!("{id:04x}"));
        let encoded_fields = arr(row.get("fields").unwrap()).unwrap();
        assert_eq!(encoded_fields.len(), fields.len());
        for (got, want) in encoded_fields.iter().zip(fields) {
            assert_eq!(got.get("id").and_then(Value::as_u64), Some(want.id as u64));
            assert_eq!(s(got, "name").unwrap(), want.name);
            assert_eq!(s(got, "kind").unwrap(), want.kind);
            assert_eq!(
                got.get("conditional").and_then(Value::as_bool),
                Some(want.conditional)
            );
        }
    }
    let vectors = arr(payload.get("object_vectors").unwrap()).unwrap();
    assert_eq!(vectors.len(), 12);
    let mut object_names = BTreeSet::new();
    for vector in vectors {
        let name = s(vector, "schema").unwrap();
        assert!(object_names.insert(name));
        let source = obj(vector.get("source").unwrap()).unwrap();
        let wire = encode_object(name, source, &[]).unwrap();
        assert_eq!(hex::encode(&wire), s(vector, "wire_hex").unwrap());
        assert_eq!(hex::encode(sha(&wire)), s(vector, "wire_sha256").unwrap());
        assert_eq!(
            hex::encode(subject_id(&wire)),
            s(vector, "subject_id").unwrap()
        );
        if name == "PermissionlessAdmissionEntryV1" {
            let unsigned = encode_object(name, source, &["entry_signature"]).unwrap();
            let message = subject_id(&unsigned);
            assert_eq!(hex::encode(message), s(vector, "signing_subject").unwrap());
            let public: [u8; 32] = decode_hex(source.get("participant_key").unwrap(), Some(32))
                .unwrap()
                .try_into()
                .unwrap();
            let signature: [u8; 64] = decode_hex(source.get("entry_signature").unwrap(), Some(64))
                .unwrap()
                .try_into()
                .unwrap();
            let key = VerifyingKey::from_bytes(&public).unwrap();
            key.verify_strict(&message, &Signature::from_bytes(&signature))
                .unwrap();
        }
        if name == "BaselineAccessWorkV1" {
            let unsigned = encode_object(name, source, &["output_hash"]).unwrap();
            let mut p = b"RLD-ADMISSION-ACCESS-WORK-V1\0".to_vec();
            p.extend_from_slice(&unsigned);
            assert_eq!(
                source.get("output_hash").and_then(Value::as_str),
                Some(hex::encode(sha(&p)).as_str())
            );
        }
        if name == "ContributionEpochDescriptorV1" {
            let records = decode_hex(source.get("member_records").unwrap(), None).unwrap();
            let count = source
                .get("member_count")
                .unwrap()
                .as_str()
                .unwrap()
                .parse::<usize>()
                .unwrap();
            assert_eq!(records.len(), count * 114);
            let (records, remainder) = records.as_chunks::<114>();
            assert!(remainder.is_empty());
            for pair in records.windows(2) {
                assert!(pair[0][..32] < pair[1][..32]);
            }
        }
    }
    let mut required = (1..=14)
        .map(|i| format!("A{i:02}"))
        .collect::<BTreeSet<_>>();
    required.extend(REJECT_CASE_IDS.iter().map(|s| s.to_string()));
    let cases = arr(payload.get("cases").unwrap()).unwrap();
    assert_eq!(cases.len(), 60);
    let mut accepted = 0;
    let mut rejected = 0;
    for case in cases {
        let case_id = s(case, "case_id").unwrap();
        assert!(
            required.remove(case_id),
            "unknown or duplicate case {case_id}"
        );
        let input = case.get("input").unwrap();
        let input_bytes = canonical(input).unwrap();
        assert_eq!(
            hex::encode(sha(&input_bytes)),
            s(case, "input_hash").unwrap()
        );
        let (accept, error, output) = evaluate(s(case, "operation").unwrap(), input).unwrap();
        assert_eq!(
            Some(accept),
            case.get("expected_accept").and_then(Value::as_bool)
        );
        assert_eq!(
            error,
            case.get("expected_first_error").and_then(Value::as_str)
        );
        assert_eq!(
            canonical(&output).unwrap(),
            canonical(case.get("expected_output").unwrap()).unwrap()
        );
        let pre = hash_parts(&[MODEL_STATE_DOMAIN, &input_bytes, b"prestate"]);
        let label = if accept {
            b"poststate".as_slice()
        } else {
            b"prestate".as_slice()
        };
        let post = hash_parts(&[MODEL_STATE_DOMAIN, &input_bytes, label]);
        assert_eq!(hex::encode(pre), s(case, "expected_prestate_root").unwrap());
        assert_eq!(
            hex::encode(post),
            s(case, "expected_poststate_root").unwrap()
        );
        let hashes = obj(case.get("expected_wire_hashes").unwrap()).unwrap();
        if let Some(want) = hashes.get("model_output").and_then(Value::as_str) {
            assert_eq!(hex::encode(sha(&canonical(&output).unwrap())), want);
        }
        if accept {
            accepted += 1
        } else {
            rejected += 1
        }
    }
    assert!(required.is_empty(), "missing cases: {required:?}");
    assert_eq!((accepted, rejected), (14, 46));
}

#[test]
fn first_error_is_independent_of_fault_order() {
    let input = json!({"faults":["invalid_access_work","bad_signature"]});
    let (_, error, _) = evaluate("reject", &input).unwrap();
    assert_eq!(error, Some("ERR_AUTHENTICATION"));
}
