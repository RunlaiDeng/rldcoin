//! Independently configured ground contacts; no discovery or ledger authority.
use crate::{contact_schema, require, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::net::Ipv4Addr;
const FORMAT: &str = "RLD-NATIVE-CONTACT-CONFIG-V1";
const MESH: &str = "RLD-CONTACT-MESH-V3";
const ZLIB: &str = "RLD-CONTACT-SPOOL-ZLIB-V1";
const ONEWAY: &str = "RLD-CONTACT-SPOOL-ONEWAY-V1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Control {
    Header {
        keys: Vec<Value>,
        version: Value,
    },
    Identifier {
        value: Value,
    },
    Capacity {
        is_list: bool,
        count: usize,
        limit: usize,
    },
    Shape {
        contact: Value,
    },
    Resolve {
        contact: Value,
        node: String,
        seen: Vec<String>,
    },
    Endpoint {
        host: Value,
        port: Value,
        listening: bool,
    },
    Spools {
        paths: Vec<String>,
        pair: bool,
    },
}
fn shape(contact: &Value) -> Result<()> {
    let object = contact.as_object().ok_or("invalid contact")?;
    let fields: Vec<&str> = object.keys().map(String::as_str).collect();
    let valid = [
        vec!["inbox", "outbox", "peer"],
        vec!["host", "peer", "port"],
        vec!["host", "peer", "port", "tls_cert_sha256"],
        vec!["adapter", "inbox", "peer"],
        vec!["adapter", "outbox", "peer"],
        vec!["adapter", "inbox", "outbox", "peer"],
    ];
    require(valid.contains(&fields), "invalid contact")?;
    if object.contains_key("adapter") {
        require(
            contact["adapter"] == ZLIB
                || (contact["adapter"] == ONEWAY
                    && (fields == vec!["adapter", "inbox", "peer"]
                        || fields == vec!["adapter", "outbox", "peer"])),
            "unsupported spool adapter",
        )?;
    }
    Ok(())
}
fn endpoint(host: &Value, port: &Value, listening: bool) -> Result<Value> {
    let text = host
        .as_str()
        .filter(|s| s.len() <= 15)
        .ok_or("TCP host must be a literal IPv4 address")?;
    let address: Ipv4Addr = text
        .parse()
        .map_err(|_| "TCP host must be a literal IPv4 address")?;
    let port = port
        .as_u64()
        .filter(|p| *p <= 65535 && (listening || *p > 0))
        .ok_or("integer outside bound")?;
    require(
        !address.is_multicast()
            && text != "255.255.255.255"
            && (listening || !address.is_unspecified()),
        "invalid TCP endpoint",
    )?;
    Ok(json!({"host":address.to_string(),"port":port}))
}
fn response(mode: &str, value: Value) -> Value {
    json!({"format":FORMAT,"mode":mode,"value":value,"configured_input_only":true,
        "ledger_authority":false,"custody_acknowledgment":false})
}
pub(crate) fn execute(request: Control) -> Result<Value> {
    let (mode, value) = match request {
        Control::Header { keys, version } => {
            let expected = ["format", "state", "network", "contacts"];
            require(
                keys.len() == 4
                    && expected
                        .iter()
                        .all(|k| keys.iter().filter(|v| *v == *k).count() == 1),
                "invalid config fields",
            )?;
            require(version == MESH, "unsupported config")?;
            ("header", Value::Null)
        }
        Control::Identifier { value } => {
            contact_schema::hex(&value)?;
            ("identifier", value)
        }
        Control::Capacity {
            is_list,
            count,
            limit,
        } => {
            require(limit <= 16, "native contact limit differs")?;
            require(is_list && count <= limit, "contact capacity reached")?;
            ("capacity", json!(count))
        }
        Control::Shape { contact } => {
            shape(&contact)?;
            ("shape", contact)
        }
        Control::Resolve {
            contact,
            node,
            seen,
        } => {
            shape(&contact)?;
            contact_schema::hex(&contact["peer"])?;
            require(
                seen.len() <= 16
                    && contact["peer"] != node
                    && !seen.iter().any(|p| contact["peer"] == *p),
                "duplicate or self contact",
            )?;
            let peer = contact["peer"].clone();
            let mut normalized = Map::new();
            if contact.as_object().is_some_and(|c| c.contains_key("host")) {
                normalized = endpoint(&contact["host"], &contact["port"], false)?
                    .as_object()
                    .ok_or("invalid TCP endpoint")?
                    .clone();
                if contact
                    .as_object()
                    .is_some_and(|c| c.contains_key("tls_cert_sha256"))
                {
                    contact_schema::hex(&contact["tls_cert_sha256"])?;
                    normalized.insert("tls_cert_sha256".into(), contact["tls_cert_sha256"].clone());
                }
            } else {
                for name in ["inbox", "outbox"] {
                    if contact.as_object().is_some_and(|c| c.contains_key(name)) {
                        normalized.insert(name.into(), contact[name].clone());
                    }
                }
                if contact["adapter"] == ZLIB {
                    normalized.insert("adapter".into(), json!(ZLIB));
                }
            }
            ("resolve", json!({"peer":peer,"contact":normalized}))
        }
        Control::Endpoint {
            host,
            port,
            listening,
        } => ("endpoint", endpoint(&host, &port, listening)?),
        Control::Spools { paths, pair } => {
            require(paths.len() <= 32, "native spool path capacity differs")?;
            for (i, path) in paths.iter().enumerate() {
                require(
                    !paths[..i].contains(path),
                    if pair {
                        "contact directions must differ"
                    } else {
                        "contact spools must be distinct"
                    },
                )?;
            }
            ("spools", Value::Null)
        }
    };
    Ok(response(mode, value))
}
