//! Signed outer exchange/TCP bindings, never durable acknowledgment or value.
use crate::{contact_crypto, contact_schema, require, wallet_client, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const FORMAT: &str = "RLD-NATIVE-CONTACT-EXCHANGE-V1";
const ADAPTER: &str = "RLD-CONTACT-TCP-V4";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    contacts: usize,
    nodes: usize,
    transits: usize,
    messages: usize,
    exchange: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.contacts <= 16
                && self.nodes <= 64
                && self.transits <= 4
                && self.messages <= 256
                && self.exchange <= 20 * 1024 * 1024,
            "native exchange limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Control {
    Exchange {
        network: String,
        signed: Value,
        peer: String,
        recipient: String,
        incoming_allowed: bool,
        limits: Limits,
    },
    Challenge {
        network: String,
        signed: Value,
        peer: String,
        fingerprint: Value,
    },
    TcpRequest {
        network: String,
        signed: Value,
        recipient: String,
        peers: Vec<String>,
        nonce: String,
        limits: Limits,
    },
    TcpResponse {
        network: String,
        signed: Value,
        requester: String,
        peer: String,
        sent: Value,
        limits: Limits,
    },
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    wallet_client::canonical_with_limit(value, 64 * 1024 * 1024)
}
fn bound(value: &Value, limit: usize, error: &str) -> Result<()> {
    require(canonical(value)?.len() <= limit, error)
}
fn response(mode: &str, network: &str, body: Value) -> Value {
    json!({"format":FORMAT,"mode":mode,"network":network,"body":body,
        "envelope_authenticated":true,"ledger_authority":false,"durable_custody_acknowledgment":false})
}
pub(crate) fn execute(request: Control) -> Result<Value> {
    match request {
        Control::Exchange {
            network,
            signed,
            peer,
            recipient,
            incoming_allowed,
            limits,
        } => {
            limits.check()?;
            let body = contact_crypto::verify_value(&network, "exchange", &signed)?;
            contact_schema::exact(
                &body,
                &[
                    "format",
                    "network",
                    "node_id",
                    "to",
                    "adverts",
                    "transits",
                    "receipts",
                    "inventory",
                ],
                "wrong contact peer",
            )?;
            require(
                body["node_id"] == peer && body["to"] == recipient,
                "wrong contact peer",
            )?;
            require(incoming_allowed, "unconfigured incoming inventory peer")?;
            let inventory = contact_schema::verify(
                &network,
                "inventory",
                &body["inventory"],
                &contact_schema::Limits::new(limits.contacts, limits.messages),
            )?;
            require(
                inventory["body"]["node_id"] == peer,
                "exchange inventory differs from sender",
            )?;
            for (field, limit) in [
                ("adverts", limits.nodes),
                ("transits", limits.transits),
                ("receipts", limits.messages),
            ] {
                require(
                    body[field].as_array().is_some_and(|v| v.len() <= limit),
                    "exchange item limit",
                )?;
            }
            Ok(response("exchange", &network, body))
        }
        Control::Challenge {
            network,
            signed,
            peer,
            fingerprint,
        } => {
            let body = contact_crypto::verify_value(&network, "tcp-challenge", &signed)?;
            contact_schema::exact(
                &body,
                &[
                    "format",
                    "adapter",
                    "network",
                    "node_id",
                    "nonce",
                    "tls_cert_sha256",
                ],
                "TCP connection challenge binding mismatch",
            )?;
            require(
                body["adapter"] == ADAPTER
                    && body["node_id"] == peer
                    && body["tls_cert_sha256"] == fingerprint,
                "TCP connection challenge binding mismatch",
            )?;
            contact_schema::hex(&body["nonce"])?;
            Ok(response("challenge", &network, body))
        }
        Control::TcpRequest {
            network,
            signed,
            recipient,
            peers,
            nonce,
            limits,
        } => {
            limits.check()?;
            require(
                peers.len() <= limits.contacts,
                "native configured peer capacity differs",
            )?;
            let body = contact_crypto::verify_value(&network, "tcp-request", &signed)?;
            contact_schema::exact(
                &body,
                &[
                    "format",
                    "adapter",
                    "network",
                    "node_id",
                    "to",
                    "nonce",
                    "challenge",
                    "bundle",
                ],
                "TCP request identity or configured peer mismatch",
            )?;
            require(
                body["adapter"] == ADAPTER
                    && body["to"] == recipient
                    && body["challenge"] == nonce
                    && body["node_id"]
                        .as_str()
                        .is_some_and(|id| peers.iter().any(|p| p == id)),
                "TCP request identity or configured peer mismatch",
            )?;
            contact_schema::hex(&body["nonce"])?;
            bound(&body["bundle"], limits.exchange, "TCP exchange byte bound")?;
            let exchange = contact_crypto::verify_value(&network, "exchange", &body["bundle"])?;
            require(
                exchange["node_id"] == body["node_id"] && exchange["to"] == recipient,
                "TCP request/bundle identity mismatch",
            )?;
            Ok(response("request", &network, body))
        }
        Control::TcpResponse {
            network,
            signed,
            requester,
            peer,
            sent,
            limits,
        } => {
            limits.check()?;
            let body = contact_crypto::verify_value(&network, "tcp-response", &signed)?;
            contact_schema::exact(
                &body,
                &[
                    "format",
                    "adapter",
                    "network",
                    "node_id",
                    "to",
                    "nonce",
                    "challenge",
                    "exchange_id",
                    "accepted",
                    "bundle",
                    "error",
                ],
                "TCP response identity, nonce or exact exchange mismatch",
            )?;
            let sent_body = sent["body"]
                .as_object()
                .ok_or("missing separately retained request body")?;
            require(
                ["nonce", "challenge", "bundle"]
                    .iter()
                    .all(|k| sent_body.contains_key(*k)),
                "missing separately retained request binding",
            )?;
            let exchange_id = hex::encode(Sha256::digest(canonical(&sent_body["bundle"])?));
            require(
                body["adapter"] == ADAPTER
                    && body["node_id"] == peer
                    && body["to"] == requester
                    && body["nonce"] == sent_body["nonce"]
                    && body["challenge"] == sent_body["challenge"]
                    && body["exchange_id"] == exchange_id,
                "TCP response identity, nonce or exact exchange mismatch",
            )?;
            let accepted = body["accepted"]
                .as_bool()
                .ok_or("invalid TCP acknowledgment")?;
            if !accepted {
                require(
                    body["bundle"].is_null() && body["error"] == "CONTACT_REJECTED",
                    "invalid TCP refusal",
                )?;
                return Err("TCP peer refused custody; retain queued evidence".into());
            }
            require(
                body["error"].is_null() && body["bundle"].is_object(),
                "invalid TCP success bundle",
            )?;
            bound(
                &body["bundle"],
                limits.exchange,
                "invalid TCP success bundle",
            )?;
            let exchange = contact_crypto::verify_value(&network, "exchange", &body["bundle"])?;
            require(
                exchange["node_id"] == peer && exchange["to"] == requester,
                "TCP response/bundle identity mismatch",
            )?;
            Ok(response("response", &network, body))
        }
    }
}
