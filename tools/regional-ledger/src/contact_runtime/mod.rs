//! Rust contact lifecycle. All wire authentication uses the existing native checks.
//! A fresh private runtime is required; legacy stores are never rewritten.
mod bft;
mod mesh;
mod service;
#[cfg(test)]
pub(crate) use bft::Runtime as TestRuntime;
pub use mesh::{initialize, Node};
pub use service::{run, Options};

pub fn tls_identity(config: &serde_json::Value) -> crate::Result<serde_json::Value> {
    let node = Node::open(config)?;
    tls(serde_json::json!({"Material":{"root":node.root,"network":node.network,"peer":node.id}}))
}

pub fn tick_transport(config: &serde_json::Value) -> crate::Result<serde_json::Value> {
    let node = Node::open(config)?;
    let contacts = node.contacts.clone();
    let root = node.root.clone();
    drop(node);
    let _lease = Lease::acquire(&root, "Service")?;
    let mut errors = Vec::new();
    if contacts
        .values()
        .all(|contact| contact.get("host").is_none())
    {
        match service::spool_directory_turn(config) {
            Ok(refused) => errors.extend(refused),
            Err(error) => errors.push(error),
        }
    } else {
        for (peer, contact) in contacts {
            let result = if contact.get("host").is_some() {
                service::outgoing(config, &peer, &contact)
            } else {
                service::spool(config, &peer, &contact)
            };
            if let Err(error) = result {
                errors.push(error);
            }
        }
    }
    let mut node = Node::open(config)?;
    node.archive_completed()?;
    Ok(
        serde_json::json!({"mesh":node.observation(),"errors":errors,"ledger_authority":false,"fixture_only":true}),
    )
}

use crate::{require, wallet_client as files, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "RLD-RUST-CONTACT-RUNTIME-V1";
pub const MESH: &str = "RLD-CONTACT-MESH-V3";
pub(crate) const STATE_LIMIT: usize = 64 * 1024 * 1024;
pub(crate) const EXCHANGE_LIMIT: usize = 20 * 1024 * 1024;
pub(crate) fn bytes(value: &Value) -> Result<Vec<u8>> {
    files::canonical_with_limit(value, STATE_LIMIT)
}
pub(crate) fn digest(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(bytes(value)?)))
}
pub(crate) fn random() -> Result<String> {
    let mut raw = [0; 32];
    getrandom::getrandom(&mut raw).map_err(|e| e.to_string())?;
    Ok(hex::encode(raw))
}
pub(crate) fn crypto(value: Value) -> Result<Value> {
    crate::contact_crypto::execute(&bytes(&value)?)
}
pub(crate) fn tls(value: Value) -> Result<Value> {
    crate::contact_tls::execute(serde_json::from_value(value).map_err(|e| e.to_string())?)
}
pub(crate) fn directory(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    crate::contact_process_lock::execute(&bytes(&json!({"Directory":{"path":absolute}}))?)?;
    Ok(absolute)
}
pub(crate) fn read(path: &Path, limit: usize) -> Result<Value> {
    let raw = files::private_read_with_limit(path, limit)?;
    let value = crate::wallet_http::decode_unique_with_limit(&raw, limit)?;
    require(
        files::canonical_with_limit(&value, limit)? == raw,
        "contact runtime requires complete canonical JSON",
    )?;
    Ok(value)
}
pub(crate) fn atomic(path: &Path, value: &Value, limit: usize) -> Result<()> {
    let raw = files::canonical_with_limit(value, limit)?;
    atomic_bytes(path, &raw, limit)
}
pub(crate) fn atomic_bytes(path: &Path, raw: &[u8], limit: usize) -> Result<()> {
    crate::contact_storage::execute(
        &bytes(&json!({"AtomicWrite":{
            "path":path,"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw)),"limit":limit
        }}))?,
        raw,
    )?;
    Ok(())
}
pub(crate) struct Lease {
    path: PathBuf,
    role: String,
    token: String,
}
impl Lease {
    pub(crate) fn acquire(path: &Path, role: &str) -> Result<Self> {
        let token = random()?[..32].to_owned();
        crate::contact_process_lock::execute(&bytes(&json!({"Acquire":{
            "token":token,"path":path,"role":role,"nonblocking":true
        }}))?)?;
        Ok(Self {
            path: path.to_owned(),
            role: role.into(),
            token,
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(raw) = bytes(&json!({"Release":{
            "token":self.token,"path":self.path,"role":self.role
        }})) {
            if let Err(error) = crate::contact_process_lock::execute(&raw) {
                eprintln!("contact runtime lock release refused: {error}");
            }
        }
    }
}
pub(crate) fn transit(
    value: &Value,
    network: &str,
    recipient: Value,
    sender: Value,
) -> Result<Value> {
    #[cfg(test)]
    let started = service::monotonic()?;
    let raw = bytes(value)?;
    let scope = json!({"mesh":MESH,"network":network,"recipient":recipient,"sender":sender,"hops":16,
        "frame":crate::contact::MAX_FRAME,"payload":crate::contact::MAX_PAYLOAD,
        "frame_format":crate::contact::FRAME_FORMAT,"frame_domain":hex::encode(format!("{}\0",crate::contact::FRAME_FORMAT)),
        "kinds":["destination-receipt","destination-sync","finalized-import","regional-bft","source-finality","source-sync"],
        "provider":{"format":"RLD-NATIVE-CONTACT-CRYPTO-V1","implementation":crate::implementation()?,"path":"rust-contact-runtime-in-process","instance":0}});
    let fields = json!({"scope":scope,"retention":512,"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(&raw))});
    #[cfg(test)]
    service::trace_subwork("transit-canonical-scope", started)?;
    #[cfg(test)]
    let started = service::monotonic()?;
    let probe = crate::contact_witness::execute(&bytes(&json!({"Probe":fields}))?, &raw)?;
    #[cfg(test)]
    service::trace_subwork(
        if probe["found"] == true {
            "transit-witness-hit"
        } else {
            "transit-witness-miss-probe"
        },
        started,
    )?;
    if probe["found"] == true {
        return Ok(
            json!({"visited":probe["visited"],"ledger_authority":false,"custody_acknowledgment":false}),
        );
    }
    #[cfg(test)]
    let started = service::monotonic()?;
    let checked = crate::contact_witness::execute(&bytes(&json!({"Check":fields}))?, &raw)?;
    #[cfg(test)]
    service::trace_subwork("transit-full-check", started)?;
    Ok(checked["verification"].clone())
}
pub(crate) fn schema(value: &Value, network: &str, kind: &str) -> Result<Value> {
    #[cfg(test)]
    let started = service::monotonic()?;
    let checked = crypto(
        json!({"Schema":{"network":network,"kind":kind,"signed":value,
        "limits":{"contacts":16,"messages":256}}}),
    )?;
    #[cfg(test)]
    service::trace_subwork(
        match kind {
            "receipt" => "receipt-schema",
            "advert" => "advert-schema",
            "inventory" => "inventory-schema",
            _ => "other-schema",
        },
        started,
    )?;
    Ok(checked)
}
pub(crate) fn exchange(value: &Value, network: &str, peer: &str, recipient: &str) -> Result<Value> {
    crypto(
        json!({"Exchange":{"Exchange":{"network":network,"signed":value,
        "peer":peer,"recipient":recipient,"incoming_allowed":true,"limits":{
            "contacts":16,"nodes":64,"transits":4,"messages":256,"exchange":EXCHANGE_LIMIT
        }}}}),
    )
}
