//! Immutable visited tuples for exact fully authenticated transit bytes only.
use crate::{contact_crypto, contact_transit, require, wallet_client, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
const FORMAT: &str = "RLD-NATIVE-TRANSIT-WITNESS-V1";
const MAX_CONTROL: usize = 8192;
const MAX_RAW: usize = 20 * 1024 * 1024;
const MAX_ENTRIES: usize = 512;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    format: String,
    implementation: String,
    path: String,
    instance: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    mesh: String,
    network: String,
    recipient: Value,
    sender: Value,
    hops: usize,
    frame: usize,
    payload: usize,
    frame_format: String,
    frame_domain: String,
    kinds: Vec<String>,
    provider: Provider,
}
impl Scope {
    fn check(&self) -> Result<()> {
        crate::Hash::from_hex(&self.network).map_err(|e| format!("{e:?}"))?;
        require(
            self.hops <= 16
                && self.frame <= crate::contact::MAX_FRAME
                && self.payload <= crate::contact::MAX_PAYLOAD,
            "native transit limits differ",
        )?;
        require(
            self.mesh.len() <= 128
                && self.frame_format.len() <= 128
                && self.frame_domain.len() <= 512
                && self.kinds.len() <= 16
                && self.kinds.iter().all(|v| v.len() <= 128)
                && self.kinds.windows(2).all(|v| v[0] < v[1]),
            "witness namespace bound/order",
        )?;
        require(
            self.provider.format == "RLD-NATIVE-CONTACT-CRYPTO-V1"
                && self.provider.implementation == hex::encode(crate::implementation()?.0)
                && self.provider.path.len() <= 4096,
            "witness provider/source differs",
        )
    }
    fn digest(&self) -> Result<[u8; 32]> {
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let raw = wallet_client::canonical_with_limit(&value, MAX_CONTROL)?;
        let mut hash = Sha256::new();
        hash.update(b"RLD-NATIVE-TRANSIT-WITNESS-SCOPE-V1\0");
        hash.update(raw);
        Ok(hash.finalize().into())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Control {
    Probe {
        scope: Scope,
        retention: usize,
        size_bytes: usize,
        sha256: String,
    },
    Check {
        scope: Scope,
        retention: usize,
        size_bytes: usize,
        sha256: String,
    },
    Clear,
    Inspect,
}
struct Entry {
    scope: [u8; 32],
    bytes: [u8; 32],
    size: usize,
    visited: Vec<[u8; 32]>,
    reused: bool,
}
struct Store {
    pid: u32,
    entries: VecDeque<Entry>,
}
fn store() -> &'static Mutex<Store> {
    static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
    STORE.get_or_init(|| {
        Mutex::new(Store {
            pid: std::process::id(),
            entries: VecDeque::new(),
        })
    })
}
fn current(store: &mut Store, retention: usize) {
    let pid = std::process::id();
    if store.pid != pid {
        store.entries.clear();
        store.pid = pid;
    }
    // A one-touch archive scan must not displace every repeatedly used path.
    // Both probation and protected recency share the unchanged total bound.
    let mut protected = store.entries.iter().filter(|entry| entry.reused).count();
    while protected > retention / 2 {
        if let Some(entry) = store.entries.iter_mut().find(|entry| entry.reused) {
            entry.reused = false;
        }
        protected -= 1;
    }
    while store.entries.len() > retention {
        let victim = store
            .entries
            .iter()
            .position(|entry| !entry.reused)
            .unwrap_or(0);
        store.entries.remove(victim);
    }
}
fn visited(values: Vec<[u8; 32]>) -> Value {
    json!(values.into_iter().map(hex::encode).collect::<Vec<_>>())
}
// A miss carries only this call's validated scope and borrowed immutable bytes.
// It never carries authentication, freshness, custody or a decoded ledger.
pub(crate) struct PreparedTransit<'a> {
    scope: Scope,
    retention: usize,
    raw: &'a [u8],
    bytes: [u8; 32],
    scope_digest: [u8; 32],
}
pub(crate) enum PreparedProbe<'a> {
    Hit(Value),
    Miss(Box<PreparedTransit<'a>>),
}
#[cfg(test)]
thread_local! {
    static INPUT_PREFLIGHTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FULL_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn control(control: &[u8]) -> Result<Control> {
    let decoded = crate::wallet_http::decode_unique_with_limit(control, MAX_CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&decoded, MAX_CONTROL)? == control,
        "witness noncanonical control",
    )?;
    serde_json::from_value(decoded).map_err(|e| e.to_string())
}
impl<'a> PreparedTransit<'a> {
    fn new(
        scope: Scope,
        retention: usize,
        size: usize,
        expected: String,
        raw: &'a [u8],
    ) -> Result<Self> {
        #[cfg(test)]
        INPUT_PREFLIGHTS.with(|count| count.set(count.get() + 1));
        scope.check()?;
        require(retention <= MAX_ENTRIES, "witness retention bound")?;
        require(
            !raw.is_empty() && raw.len() <= MAX_RAW && raw.len() == size,
            "witness complete byte bound",
        )?;
        let bytes: [u8; 32] = Sha256::digest(raw).into();
        require(
            hex::encode(bytes) == expected,
            "witness complete bytes differ",
        )?;
        let scope_digest = scope.digest()?;
        Ok(Self {
            scope,
            retention,
            raw,
            bytes,
            scope_digest,
        })
    }
    fn probe(&self) -> Result<Option<Vec<[u8; 32]>>> {
        let mut store = store().lock().map_err(|_| "witness lock poisoned")?;
        current(&mut store, self.retention);
        let mut found = None;
        if let Some(index) = store.entries.iter().position(|v| {
            v.scope == self.scope_digest && v.bytes == self.bytes && v.size == self.raw.len()
        }) {
            let mut entry = store.entries.remove(index).ok_or("witness entry absent")?;
            entry.reused = true;
            found = Some(entry.visited.clone());
            store.entries.push_back(entry);
            current(&mut store, self.retention);
        }
        Ok(found)
    }
    fn response(&self, check: bool, found: Option<Vec<[u8; 32]>>, verification: Value) -> Value {
        let authenticated = found.is_some();
        json!({"format":FORMAT,"mode":if check{"check"}else{"probe"},"network":self.scope.network,"scope_sha256":hex::encode(self.scope_digest),
            "transit_sha256":hex::encode(self.bytes),"size_bytes":self.raw.len(),"found":authenticated,"visited":found.map(visited),"verification":verification,
            "transport_authenticated":check||authenticated,"ledger_authority":false,"custody_acknowledgment":false})
    }
    pub(crate) fn check(self) -> Result<Value> {
        #[cfg(test)]
        FULL_CHECKS.with(|count| count.set(count.get() + 1));
        // No witness lock during complete original signature/frame/hop checks.
        // The borrowed raw cannot change between preflight and this consuming call.
        let transit = crate::wallet_http::decode_unique_with_limit(self.raw, MAX_RAW)?;
        require(
            wallet_client::canonical_with_limit(&transit, MAX_RAW)? == self.raw,
            "witness noncanonical transit",
        )?;
        let request=serde_json::from_value::<contact_transit::Request>(json!({"Check":{"network":self.scope.network,
            "limits":{"hops":self.scope.hops,"frame":self.scope.frame,"payload":self.scope.payload},"transit":transit,
            "recipient":self.scope.recipient,"sender":self.scope.sender}})).map_err(|e|e.to_string())?;
        let verification = contact_transit::execute(request)?;
        let values = verification["visited"]
            .as_array()
            .ok_or("witness verified path absent")?;
        require(values.len() <= 17, "witness verified path bound")?;
        let values = values
            .iter()
            .map(|v| -> Result<_> {
                crate::Hash::from_hex(v.as_str().ok_or("witness path identity")?)
                    .map(|h| h.0)
                    .map_err(|e| format!("{e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut store = store().lock().map_err(|_| "witness lock poisoned")?;
        current(&mut store, self.retention);
        if self.retention > 0 {
            let reused = store.entries.iter().any(|v| {
                v.scope == self.scope_digest
                    && v.bytes == self.bytes
                    && v.size == self.raw.len()
                    && v.reused
            });
            store.entries.retain(|v| {
                !(v.scope == self.scope_digest && v.bytes == self.bytes && v.size == self.raw.len())
            });
            store.entries.push_back(Entry {
                scope: self.scope_digest,
                bytes: self.bytes,
                size: self.raw.len(),
                visited: values.clone(),
                reused,
            });
            current(&mut store, self.retention);
        }
        drop(store);
        Ok(self.response(true, Some(values), verification))
    }
}
/// Internal same-call optimization. A miss is not an authenticated result.
/// Explicit public Check retains its unconditional full-verification semantics.
pub(crate) fn prepare_probe<'a>(control_bytes: &[u8], raw: &'a [u8]) -> Result<PreparedProbe<'a>> {
    let Control::Probe {
        scope,
        retention,
        size_bytes,
        sha256,
    } = control(control_bytes)?
    else {
        return Err("prepared witness requires Probe".into());
    };
    let prepared = PreparedTransit::new(scope, retention, size_bytes, sha256, raw)?;
    match prepared.probe()? {
        Some(found) => Ok(PreparedProbe::Hit(prepared.response(
            false,
            Some(found),
            Value::Null,
        ))),
        None => Ok(PreparedProbe::Miss(Box::new(prepared))),
    }
}
pub(crate) fn execute(control_bytes: &[u8], raw: &[u8]) -> Result<Value> {
    let request = control(control_bytes)?;
    let (scope, retention, size, expected, check) = match request {
        Control::Probe {
            scope,
            retention,
            size_bytes,
            sha256,
        } => (scope, retention, size_bytes, sha256, false),
        Control::Check {
            scope,
            retention,
            size_bytes,
            sha256,
        } => (scope, retention, size_bytes, sha256, true),
        Control::Clear | Control::Inspect => {
            require(raw.is_empty(), "witness diagnostics payload refused")?;
            let clear = matches!(request, Control::Clear);
            let mut store = store().lock().map_err(|_| "witness lock poisoned")?;
            current(&mut store, MAX_ENTRIES);
            if clear {
                store.entries.clear();
            }
            return Ok(
                json!({"format":FORMAT,"mode":if clear{"clear"}else{"inspect"},"entries":store.entries.len(),
                "values":store.entries.iter().map(|v|visited(v.visited.clone())).collect::<Vec<_>>(),"ledger_authority":false,"custody_acknowledgment":false}),
            );
        }
    };
    let prepared = PreparedTransit::new(scope, retention, size, expected, raw)?;
    if check {
        prepared.check()
    } else {
        let found = prepared.probe()?;
        Ok(prepared.response(false, found, Value::Null))
    }
}

const PROBE_FORMAT: &str = "RLD-NATIVE-TRANSIT-WITNESS-PROBE-V1";
const PROBE_CODEC: &[u8] = b"RLD-TRANSIT-WITNESS-PROBE-BYTES-V1\0";
fn probe_bytes(control: &[u8], raw: &[u8]) -> Result<Value> {
    let header = PROBE_CODEC.len() + 2 + 4 + 8 + 32;
    require(
        control.len() >= header && &control[..PROBE_CODEC.len()] == PROBE_CODEC,
        "witness probe codec/incomplete header",
    )?;
    let mut at = PROBE_CODEC.len();
    let retention = u16::from_be_bytes(
        control[at..at + 2]
            .try_into()
            .map_err(|_| "witness retention length")?,
    ) as usize;
    at += 2;
    let scope_len = u32::from_be_bytes(
        control[at..at + 4]
            .try_into()
            .map_err(|_| "witness scope length")?,
    ) as usize;
    at += 4;
    let size = u64::from_be_bytes(
        control[at..at + 8]
            .try_into()
            .map_err(|_| "witness size length")?,
    );
    at += 8;
    let expected = &control[at..at + 32];
    at += 32;
    require(
        retention <= MAX_ENTRIES
            && scope_len > 0
            && scope_len <= MAX_CONTROL
            && at.checked_add(scope_len) == Some(control.len())
            && !raw.is_empty()
            && raw.len() <= MAX_RAW
            && size == raw.len() as u64,
        "witness probe capacity/EOF/size",
    )?;
    let bytes: [u8; 32] = Sha256::digest(raw).into();
    require(
        bytes.as_slice() == expected,
        "witness complete bytes differ",
    )?;
    // A hit requires the hash of the complete CURRENT scope bytes to match the
    // canonical scope of a previously fully verified Check. No supplied hash
    // or unvalidated control can insert or replace a witness. Misses stay cold.
    let mut scope = Sha256::new();
    scope.update(b"RLD-NATIVE-TRANSIT-WITNESS-SCOPE-V1\0");
    scope.update(&control[at..]);
    let scope: [u8; 32] = scope.finalize().into();
    let mut store = store().lock().map_err(|_| "witness lock poisoned")?;
    current(&mut store, retention);
    let mut found = None;
    if let Some(index) = store
        .entries
        .iter()
        .position(|v| v.scope == scope && v.bytes == bytes && v.size == raw.len())
    {
        let mut entry = store.entries.remove(index).ok_or("witness entry absent")?;
        entry.reused = true;
        found = Some(entry.visited.clone());
        store.entries.push_back(entry);
        current(&mut store, retention);
    }
    let authenticated = found.is_some();
    Ok(
        json!({"format":PROBE_FORMAT,"scope_sha256":hex::encode(scope),"transit_sha256":hex::encode(bytes),"size_bytes":raw.len(),
        "found":authenticated,"visited":found.map(visited),"transport_authenticated":authenticated,"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
/// # Safety
/// Both inputs must remain immutable/readable. Invalid bounds are not read.
/// Free the returned buffer exactly once; this entry never inserts a witness.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_transit_witness_probe(
    control: *const u8,
    control_len: usize,
    input: *const u8,
    len: usize,
) -> contact_crypto::Buffer {
    let valid = !control.is_null()
        && control_len > 0
        && control_len <= MAX_CONTROL + 128
        && !input.is_null()
        && len > 0
        && len <= MAX_RAW;
    let ctrl = if valid {
        unsafe { std::slice::from_raw_parts(control, control_len) }
    } else {
        &[]
    };
    let raw = if valid {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    contact_crypto::buffer(contact_crypto::output_with(ctrl, || {
        require(valid, "witness probe ABI input bound")?;
        probe_bytes(ctrl, raw)
    }))
}
pub(crate) fn is_result(value: &Value) -> bool {
    value.as_object().is_some_and(|v| {
        v.get("format")
            .is_some_and(|f| f == FORMAT || f == PROBE_FORMAT)
    })
}
/// # Safety
/// Both inputs stay immutable/readable for the call. Oversized inputs are not
/// read. Release the exact returned common buffer once. Probe never inserts;
/// only complete native Check can retain immutable visited identities.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_transit_witness(
    control: *const u8,
    control_len: usize,
    input: *const u8,
    len: usize,
) -> contact_crypto::Buffer {
    let valid = !control.is_null()
        && control_len > 0
        && control_len <= MAX_CONTROL
        && len <= MAX_RAW
        && (len == 0 || !input.is_null());
    let ctrl = if valid {
        unsafe { std::slice::from_raw_parts(control, control_len) }
    } else {
        &[]
    };
    let raw = if valid && len > 0 {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    contact_crypto::buffer(contact_crypto::output_with(ctrl, || {
        require(valid, "witness ABI input bound")?;
        execute(ctrl, raw)
    }))
}

#[cfg(test)]
#[path = "contact_witness_tests.rs"]
mod tests;
