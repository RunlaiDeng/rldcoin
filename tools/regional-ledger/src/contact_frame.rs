//! Bounded opaque carriage frames, never native evidence/value authentication.
use crate::{
    contact::{Frame, FRAME_FORMAT, MAX_FRAME, MAX_PAYLOAD},
    contact_crypto::{buffer, output_with},
    contact_spool_codec::CodecOutput,
    require, wallet_client, Hash, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const FORMAT: &str = "RLD-NATIVE-CONTACT-FRAME-V1";
const CONTROL: usize = 8192;
const KINDS: [&str; 7] = [
    "destination-receipt",
    "destination-sync",
    "finalized-import",
    "onward-source-finality",
    "regional-bft",
    "source-finality",
    "source-sync",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    payload: usize,
    frame: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.payload <= MAX_PAYLOAD && self.frame <= MAX_FRAME,
            "native frame limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Make {
        kind: String,
        source: String,
        destination: String,
        export: String,
        limits: Limits,
        size_bytes: usize,
        sha256: String,
    },
    Inspect {
        source: Option<String>,
        destination: Option<String>,
        limits: Limits,
        size_bytes: usize,
        sha256: String,
    },
}
fn sha(raw: &[u8]) -> Hash {
    Hash(Sha256::digest(raw).into())
}
fn hex(value: &str, name: &str) -> Result<Hash> {
    Hash::from_hex(value).map_err(|_| format!("invalid {name}"))
}
fn bound(raw: &[u8], size: usize, expected: &str) -> Result<Hash> {
    let hash = sha(raw);
    require(
        raw.len() == size && hex::encode(hash.0) == expected,
        "native frame payload binding differs",
    )?;
    Ok(hash)
}
fn metadata(frame: &Frame, frame_size: usize, frame_hash: Hash, payload_size: usize) -> Value {
    json!({"format":FORMAT,"frame_size":frame_size,"frame_sha256":frame_hash,
        "payload_size":payload_size,"payload_sha256":frame.payload_sha256,
        "message_id":frame.message_id,"ledger_authority":false,"authenticated":false})
}
fn inspect_regional(frame: &Frame, payload: &[u8], network: Option<&str>) -> Result<()> {
    let value = crate::wallet_http::decode_unique_with_limit(payload, MAX_PAYLOAD)?;
    let object = value
        .as_object()
        .ok_or("regional consensus carriage binding mismatch")?;
    let origin = value["format"] == "RLD-REGIONAL-BFT-ORIGIN-NETWORK-V3";
    let onward = value["format"] == crate::bft_onward_network::FORMAT;
    let mut fields = vec!["format", "currency", "region", "evidence", "body"];
    if origin {
        fields.push("origins");
    }
    if onward {
        fields.push("history");
    }
    require(
        object.len() == fields.len()
            && fields.iter().all(|k| object.contains_key(*k))
            && (origin || onward || value["format"] == "RLD-REGIONAL-BFT-NETWORK-V2")
            && (!origin || value["origins"].as_array().is_some_and(|v| v.len() <= 4))
            && (!onward || value["history"].is_null() || value["history"].is_object())
            && value["region"] == hex::encode(frame.source_chain_id.0)
            && frame.export_id == frame.payload_sha256,
        "regional consensus carriage binding mismatch",
    )?;
    hex(
        value["currency"]
            .as_str()
            .ok_or("invalid consensus currency")?,
        "consensus currency",
    )?;
    if let Some(network) = network {
        require(
            value["currency"] == network,
            "consensus carriage differs from mesh currency",
        )?;
    }
    Ok(())
}
pub(super) fn inspect_bytes(
    raw: &[u8],
    source: Option<String>,
    destination: Option<String>,
    payload_bound: usize,
    frame_bound: usize,
) -> Result<(Frame, Vec<u8>)> {
    inspect_bytes_with_network(raw, source, destination, payload_bound, frame_bound, None)
}
pub(super) fn inspect_bytes_with_network(
    raw: &[u8],
    source: Option<String>,
    destination: Option<String>,
    payload_bound: usize,
    frame_bound: usize,
    network: Option<&str>,
) -> Result<(Frame, Vec<u8>)> {
    let limits = Limits {
        payload: payload_bound,
        frame: frame_bound,
    };
    limits.check()?;
    require(
        !raw.is_empty() && raw.len() <= limits.frame,
        "frame exceeds bound",
    )?;
    let value = crate::wallet_http::decode_unique_with_limit(raw, limits.frame)?;
    let frame: Frame = serde_json::from_value(value).map_err(|_| "invalid evidence frame")?;
    require(
        frame.format == FRAME_FORMAT && KINDS.contains(&frame.kind.as_str()),
        "invalid evidence frame",
    )?;
    require(
        frame.retained_bytes()? == raw,
        "noncanonical evidence frame",
    )?;
    require(
        (frame.source_chain_id == frame.destination_chain_id) == (frame.kind == "regional-bft"),
        "same-chain evidence frame",
    )?;
    if let Some(source) = source {
        require(
            hex::encode(frame.source_chain_id.0) == source,
            "wrong source chain",
        )?;
    }
    if let Some(destination) = destination {
        require(
            hex::encode(frame.destination_chain_id.0) == destination,
            "wrong destination chain",
        )?;
    }
    require(
        frame.payload_b64.len() <= limits.payload.div_ceil(3) * 4,
        "payload changed",
    )?;
    let payload = STANDARD
        .decode(&frame.payload_b64)
        .map_err(|_| "invalid payload encoding")?;
    require(
        !payload.is_empty()
            && payload.len() <= limits.payload
            && STANDARD.encode(&payload) == frame.payload_b64
            && sha(&payload) == frame.payload_sha256,
        "payload changed",
    )?;
    require(frame.message()? == frame.message_id, "message ID changed")?;
    if frame.kind == "regional-bft" {
        inspect_regional(&frame, &payload, network)?;
    }
    Ok((frame, payload))
}
fn execute(control: &[u8], raw: &[u8]) -> Result<(Value, Vec<u8>)> {
    let value = crate::wallet_http::decode_unique_with_limit(control, CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&value, CONTROL)? == control,
        "native frame noncanonical control",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    match request {
        Request::Info => {
            require(raw.is_empty(), "native frame unexpected payload")?;
            Ok((
                json!({"format":FORMAT,"frame":FRAME_FORMAT,"kinds":KINDS,
                "max_payload":MAX_PAYLOAD,"max_frame":MAX_FRAME,"max_control":CONTROL,
                "ledger_authority":false,"authenticated":false}),
                vec![],
            ))
        }
        Request::Make {
            kind,
            source,
            destination,
            export,
            limits,
            size_bytes,
            sha256,
        } => {
            limits.check()?;
            require(
                KINDS.contains(&kind.as_str()) && !raw.is_empty() && raw.len() <= limits.payload,
                "invalid kind or payload length",
            )?;
            let payload_hash = bound(raw, size_bytes, &sha256)?;
            let mut frame = Frame {
                format: FRAME_FORMAT.into(),
                kind,
                source_chain_id: hex(&source, "source chain")?,
                destination_chain_id: hex(&destination, "destination chain")?,
                export_id: hex(&export, "export ID")?,
                payload_sha256: payload_hash,
                payload_b64: STANDARD.encode(raw),
                message_id: Hash::ZERO,
            };
            require(
                (frame.source_chain_id == frame.destination_chain_id)
                    == (frame.kind == "regional-bft"),
                "source and destination are the same chain",
            )?;
            frame.message_id = frame.message()?;
            let encoded = frame.retained_bytes()?;
            require(encoded.len() <= limits.frame, "frame exceeds bound")?;
            Ok((
                metadata(&frame, encoded.len(), sha(&encoded), raw.len()),
                encoded,
            ))
        }
        Request::Inspect {
            source,
            destination,
            limits,
            size_bytes,
            sha256,
        } => {
            limits.check()?;
            require(
                !raw.is_empty() && raw.len() <= limits.frame,
                "frame exceeds bound",
            )?;
            let input_hash = bound(raw, size_bytes, &sha256)?;
            let (frame, payload) =
                inspect_bytes(raw, source, destination, limits.payload, limits.frame)?;
            Ok((
                metadata(&frame, raw.len(), input_hash, payload.len()),
                payload,
            ))
        }
    }
}
/// # Safety
/// Declared pointers are immutable/readable for this call. Oversized inputs are
/// not read. Release both unchanged result buffers once through this library.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_frame(
    input: *const u8,
    len: usize,
    payload: *const u8,
    size: usize,
) -> CodecOutput {
    let control_ok = !input.is_null() && len > 0 && len <= CONTROL;
    let valid = control_ok && size <= MAX_FRAME && (size == 0 || !payload.is_null());
    let control = if control_ok {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let raw = if valid && size > 0 {
        unsafe { std::slice::from_raw_parts(payload, size) }
    } else {
        &[]
    };
    let checked = std::panic::catch_unwind(|| {
        require(valid, "native frame ABI bounds differ")?;
        execute(control, raw)
    })
    .unwrap_or_else(|_| Err("native frame panic refused".into()));
    let (result, bytes) = match checked {
        Ok((value, bytes)) => (Ok(value), bytes),
        Err(error) => (Err(error), vec![]),
    };
    CodecOutput {
        receipt: buffer(output_with(control, || result)),
        payload: buffer(bytes),
    }
}
