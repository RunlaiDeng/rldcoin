//! Complete signed carriage composition; no ledger or custody authorization.
use crate::{contact_crypto, contact_frame, contact_schema, require, wallet_client, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const FORMAT: &str = "RLD-NATIVE-CONTACT-TRANSIT-V1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    hops: usize,
    frame: usize,
    payload: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.hops <= 16
                && self.frame <= crate::contact::MAX_FRAME
                && self.payload <= crate::contact::MAX_PAYLOAD,
            "native transit limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Request {
    Packet {
        network: String,
        limits: Limits,
        signed: Value,
    },
    Check {
        network: String,
        limits: Limits,
        transit: Value,
        recipient: Value,
        sender: Value,
    },
}
fn digest(value: &Value) -> Result<String> {
    let raw = wallet_client::canonical_with_limit(value, 64 * 1024 * 1024)?;
    Ok(hex::encode(Sha256::digest(raw)))
}
fn packet(value: &Value, network: &str, limits: &Limits) -> Result<(Value, Value)> {
    let body = contact_crypto::verify_value(network, "packet", value)?;
    contact_schema::exact(
        &body,
        &[
            "format",
            "network",
            "node_id",
            "destination",
            "nonce",
            "hop_limit",
            "frame",
        ],
        "invalid packet fields",
    )?;
    contact_schema::hex(&body["destination"])?;
    contact_schema::hex(&body["nonce"])?;
    require(
        body["hop_limit"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= limits.hops as u64),
        "integer outside bound",
    )?;
    let encoded = body["frame"].as_str().ok_or("frame outside bound")?;
    require(encoded.len() <= limits.frame * 2, "frame outside bound")?;
    let raw = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid frame encoding")?;
    require(
        STANDARD.encode(&raw) == encoded,
        "noncanonical frame encoding",
    )?;
    let (frame, _) = contact_frame::inspect_bytes_with_network(
        &raw,
        None,
        None,
        limits.payload,
        limits.frame,
        Some(network),
    )?;
    Ok((
        body,
        serde_json::to_value(frame).map_err(|e| e.to_string())?,
    ))
}
fn response(mode: &str, network: &str, body: Value, frame: Value, visited: Vec<Value>) -> Value {
    json!({"format":FORMAT,"mode":mode,"network":network,"body":body,"frame":frame,"visited":visited,
        "transport_authenticated":true,"ledger_authority":false,"custody_acknowledgment":false})
}
pub(crate) fn execute(request: Request) -> Result<Value> {
    match request {
        Request::Packet {
            network,
            limits,
            signed,
        } => {
            limits.check()?;
            let (body, frame) = packet(&signed, &network, &limits)?;
            Ok(response("packet", &network, body, frame, vec![]))
        }
        Request::Check {
            network,
            limits,
            transit,
            recipient,
            sender,
        } => {
            limits.check()?;
            contact_schema::exact(
                &transit,
                &["packet", "routing", "hops"],
                "invalid transit fields",
            )?;
            let (body, frame) = packet(&transit["packet"], &network, &limits)?;
            let packet_id = digest(&transit["packet"])?;
            let route = contact_schema::route(&transit["routing"], &network)?;
            require(
                route["node_id"] == body["node_id"]
                    && route["packet_id"] == packet_id
                    && route["destination"] == body["destination"]
                    && route["frame_id"] == frame["message_id"],
                "receipt routing certificate differs from signed packet",
            )?;
            let hops = transit["hops"].as_array().ok_or("hop limit exceeded")?;
            require(
                hops.len() <= body["hop_limit"].as_u64().ok_or("integer outside bound")? as usize,
                "hop limit exceeded",
            )?;
            let mut previous = Value::String(packet_id.clone());
            let mut current = body["node_id"].clone();
            let mut visited = vec![current.clone()];
            for hop in hops {
                let signed = contact_crypto::verify_value(&network, "hop", hop)?;
                contact_schema::exact(
                    &signed,
                    &[
                        "format",
                        "network",
                        "node_id",
                        "packet_id",
                        "previous",
                        "to",
                    ],
                    "invalid hop fields",
                )?;
                contact_schema::hex(&signed["to"])?;
                require(
                    signed["node_id"] == current
                        && signed["previous"] == previous
                        && signed["packet_id"] == packet_id,
                    "broken signed hop chain",
                )?;
                require(!visited.contains(&signed["to"]), "routing loop")?;
                current = signed["to"].clone();
                previous = Value::String(digest(hop)?);
                visited.push(current.clone());
            }
            if !recipient.is_null() {
                require(
                    !hops.is_empty()
                        && current == recipient
                        && hops.last().is_some_and(|h| h["body"]["node_id"] == sender),
                    "hop does not authorize this contact",
                )?;
            }
            Ok(response("transit", &network, body, frame, visited))
        }
    }
}
