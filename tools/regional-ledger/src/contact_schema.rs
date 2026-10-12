//! Complete signed transport metadata checks; labels/routes grant no ledger rights.
use crate::{contact_crypto, require, Result};
use serde::Deserialize;
use serde_json::{json, Value};
const FORMAT: &str = "RLD-NATIVE-CONTACT-SCHEMA-V1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    contacts: usize,
    messages: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.contacts <= 16 && self.messages <= 256,
            "native contact schema limits differ",
        )
    }
}
fn exact(body: &Value, fields: &[&str], error: &str) -> Result<()> {
    let map = body.as_object().ok_or(error)?;
    require(
        map.len() == fields.len() && fields.iter().all(|k| map.contains_key(*k)),
        error,
    )
}
fn hex(value: &Value) -> Result<()> {
    require(
        value.as_str().is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        "invalid 32-byte hex",
    )
}
fn ordered(values: &[Value], error: &str) -> Result<()> {
    require(
        values
            .windows(2)
            .all(|v| v[0].as_str().zip(v[1].as_str()).is_some_and(|(a, b)| a < b)),
        error,
    )
}
fn advert(body: &Value, limits: &Limits) -> Result<()> {
    exact(
        body,
        &[
            "format",
            "network",
            "node_id",
            "region",
            "label",
            "sequence",
            "neighbors",
        ],
        "invalid advertisement fields",
    )?;
    hex(&body["region"])?;
    require(
        body["label"].as_str().is_some_and(|s| {
            !s.is_empty() && s.len() <= 80 && s.is_ascii() && s.bytes().all(|b| b >= 32)
        }),
        "invalid display label",
    )?;
    require(
        body["sequence"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= i64::MAX as u64),
        "integer outside bound",
    )?;
    let peers = body["neighbors"]
        .as_array()
        .ok_or("invalid neighbor list")?;
    require(
        peers.len() <= limits.contacts && peers.iter().all(|v| v.is_string()),
        "invalid neighbor list",
    )?;
    ordered(peers, "invalid neighbor order or duplicate")?;
    for peer in peers {
        hex(peer)?;
        require(*peer != body["node_id"], "self contact")?;
    }
    Ok(())
}
fn inventory(body: &Value, limits: &Limits) -> Result<()> {
    exact(
        body,
        &["format", "network", "node_id", "packet_ids"],
        "invalid peer inventory capacity/schema",
    )?;
    let ids = body["packet_ids"]
        .as_array()
        .ok_or("invalid peer inventory capacity/schema")?;
    require(
        ids.len() <= limits.messages,
        "invalid peer inventory capacity/schema",
    )?;
    for id in ids {
        hex(id)?;
    }
    ordered(ids, "peer inventory duplicate/order invalid")
}
fn route(value: &Value, network: &str) -> Result<Value> {
    let body = contact_crypto::verify_value(network, "receipt-route", value)?;
    exact(
        &body,
        &[
            "format",
            "network",
            "node_id",
            "packet_id",
            "destination",
            "frame_id",
        ],
        "invalid source-signed receipt routing certificate",
    )?;
    for name in ["packet_id", "destination", "frame_id"] {
        hex(&body[name])?;
    }
    Ok(body)
}
pub(crate) fn verify(network: &str, kind: &str, value: &Value, limits: &Limits) -> Result<Value> {
    limits.check()?;
    require(
        matches!(kind, "advert" | "inventory" | "receipt-route" | "receipt"),
        "native contact schema kind differs",
    )?;
    // Each received envelope is authenticated, including the nested route.
    let body = if kind == "receipt-route" {
        route(value, network)?
    } else {
        contact_crypto::verify_value(network, kind, value)?
    };
    match kind {
        "advert" => advert(&body, limits)?,
        "inventory" => inventory(&body, limits)?,
        "receipt-route" => {}
        "receipt" => {
            exact(
                &body,
                &[
                    "format",
                    "network",
                    "node_id",
                    "packet_id",
                    "frame_id",
                    "routing",
                    "outcome",
                ],
                "invalid receipt fields",
            )?;
            hex(&body["packet_id"])?;
            hex(&body["frame_id"])?;
            require(
                body["outcome"] == "EVIDENCE_STORED_NOT_LEDGER_ACCEPTED",
                "wrong receipt outcome",
            )?;
            let routing = route(&body["routing"], network)?;
            require(
                body["node_id"] == routing["destination"]
                    && body["packet_id"] == routing["packet_id"]
                    && body["frame_id"] == routing["frame_id"],
                "wrong destination receipt",
            )?;
        }
        _ => unreachable!(),
    }
    Ok(
        json!({"format":FORMAT,"kind":kind,"network":network,"body":body,
  "transport_authenticated":true,"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
