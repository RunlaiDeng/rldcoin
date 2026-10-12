//! Transport identity/signature backend, never ledger, custody or finality authority.
use crate::{require, wallet_client as files, Hash, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const FORMAT: &str = "RLD-NATIVE-CONTACT-CRYPTO-V1";
const MESH: &str = "RLD-CONTACT-MESH-V3";
const ACTIVE: &str = "RLD-CONTACT-ACTIVE-SHARED-FRAME-V1";
const ARCHIVE: &str = "RLD-CONTACT-ARCHIVE-SHARED-FRAME-V1";
const RECEIPT: &str = "RLD-CONTACT-RECEIPT-SCHEDULER-V2";
const TRANSIT: &str = "RLD-CONTACT-TRANSIT-SCHEDULER-V33";
// Existing mesh document ceiling, distinct from 20-MiB exchanges and 8-MiB ledgers.
const MAX_OBJECT: usize = 64 * 1024 * 1024;
pub const MAX_ABI: usize = MAX_OBJECT + 16384;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    transit_scheduler: String,
    active_storage: String,
    format: String,
    archive_storage: String,
    receipt_scheduler: String,
    network: String,
    region: String,
    label: String,
    public_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    body: Value,
    public_key: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Tls(crate::contact_tls::Request),
    Transit(crate::contact_transit::Request),
    Exchange(crate::contact_exchange::Control),
    Config(crate::contact_config::Control),
    Initialize {
        root: PathBuf,
        network: String,
        region: String,
        label: String,
    },
    Inspect {
        identity: PathBuf,
        network: String,
    },
    Sign {
        identity: PathBuf,
        network: String,
        public_key: String,
        kind: String,
        body: Value,
    },
    Verify {
        network: String,
        kind: String,
        signed: Signed,
    },
    Schema {
        network: String,
        kind: String,
        limits: crate::contact_schema::Limits,
        signed: Value,
    },
}
pub(crate) fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N]> {
    require(
        text.len() == 2 * N
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "contact lowercase hex encoding",
    )?;
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn node_id(public: &str) -> Result<String> {
    let bytes = hex_bytes::<32>(public)?;
    let mut hash = Sha256::new();
    hash.update(b"RLD-CONTACT-MESH-V3\0node\0");
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}
fn label_check(label: &str) -> Result<()> {
    require(
        !label.is_empty()
            && label.len() <= 80
            && label.is_ascii()
            && label.bytes().all(|b| b >= 32),
        "contact identity display label",
    )
}
fn identity_check(identity: &Identity, network: &str) -> Result<()> {
    require(
        identity.format == MESH
            && identity.active_storage == ACTIVE
            && identity.archive_storage == ARCHIVE
            && identity.receipt_scheduler == RECEIPT
            && identity.transit_scheduler == TRANSIT
            && identity.network == network,
        "contact identity network/storage differs",
    )?;
    hex_bytes::<32>(&identity.network)?;
    hex_bytes::<32>(&identity.region)?;
    label_check(&identity.label)?;
    hex_bytes::<32>(&identity.public_key)?;
    Ok(())
}
pub(crate) fn private_root(root: &Path) -> Result<()> {
    files::private_path(root, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        require(
            meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
            "contact private directory owner/permissions",
        )?;
    }
    Ok(())
}
fn inspect(path: &Path, network: &str) -> Result<(Identity, SigningKey)> {
    require(
        path.file_name()
            .is_some_and(|n| n == "identity.private.json"),
        "contact identity file purpose differs",
    )?;
    private_root(path.parent().ok_or("contact identity parent absent")?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            fs::symlink_metadata(path)
                .map_err(|e| e.to_string())?
                .nlink()
                == 1,
            "contact private identity hardlink refused",
        )?;
    }
    let raw = Zeroizing::new(files::private_read_with_limit(path, 8192)?);
    let mut value = crate::wallet_http::decode_unique(&raw)?;
    let canonical = Zeroizing::new(files::canonical_with_limit(&value, 8192)?);
    require(
        *raw == *canonical,
        "contact private identity canonical encoding",
    )?;
    let secret = match value
        .as_object_mut()
        .ok_or("contact identity shape")?
        .remove("private_key")
    {
        Some(Value::String(secret)) => Zeroizing::new(secret),
        _ => return Err("contact private key field differs".into()),
    };
    let identity: Identity = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    require(
        serde_json::to_value(&identity).map_err(|e| e.to_string())? == value,
        "contact identity typed fields differ",
    )?;
    identity_check(&identity, network)?;
    let seed = Zeroizing::new(hex_bytes::<32>(&secret)?);
    let key = SigningKey::from_bytes(&seed);
    require(
        hex::encode(key.verifying_key().as_bytes()) == identity.public_key,
        "contact identity private/public pair differs",
    )?;
    Ok((identity, key))
}
fn public_identity(identity: Identity) -> Result<Value> {
    let mut value = serde_json::to_value(&identity).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("contact public identity shape")?
        .insert(
            "node_id".into(),
            Value::String(node_id(&identity.public_key)?),
        );
    Ok(value)
}
fn initialize(root: &Path, network: String, region: String, label: String) -> Result<Value> {
    private_root(root)?;
    hex_bytes::<32>(&network)?;
    hex_bytes::<32>(&region)?;
    label_check(&label)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|e| e.to_string())?;
    let key = SigningKey::from_bytes(&seed);
    let identity = Identity {
        transit_scheduler: TRANSIT.into(),
        active_storage: ACTIVE.into(),
        format: MESH.into(),
        archive_storage: ARCHIVE.into(),
        receipt_scheduler: RECEIPT.into(),
        network,
        region,
        label,
        public_key: hex::encode(key.verifying_key().as_bytes()),
    };
    let mut value = serde_json::to_value(&identity).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("contact identity shape")?
        .insert("private_key".into(), Value::String(hex::encode(*seed)));
    let raw = Zeroizing::new(files::canonical_with_limit(&value, 8192)?);
    if let Some(Value::String(mut secret)) =
        value.as_object_mut().and_then(|v| v.remove("private_key"))
    {
        secret.zeroize();
    }
    let path = root.join("identity.private.json");
    let mut file = files::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&raw).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    public_identity(identity)
}
fn domain(kind: &str) -> Result<Vec<u8>> {
    require(
        matches!(
            kind,
            "advert"
                | "archive"
                | "exchange"
                | "hop"
                | "inventory"
                | "packet"
                | "receipt"
                | "receipt-route"
                | "tcp-challenge"
                | "tcp-request"
                | "tcp-response"
        ),
        "contact signing domain differs",
    )?;
    Ok(format!("{MESH}\0{kind}\0").into_bytes())
}
fn body_check(body: &Value, network: &str, public: &str) -> Result<()> {
    hex_bytes::<32>(network)?;
    let map = body.as_object().ok_or("contact body object required")?;
    require(
        map.get("format").and_then(Value::as_str) == Some(MESH)
            && map.get("network").and_then(Value::as_str) == Some(network)
            && map.get("node_id").and_then(Value::as_str) == Some(node_id(public)?.as_str()),
        "contact body network/version/identity differs",
    )
}
fn signature_bytes(kind: &str, body: &Value) -> Result<Vec<u8>> {
    let mut bytes = domain(kind)?;
    bytes.extend(files::canonical_with_limit(body, MAX_OBJECT)?);
    Ok(bytes)
}
fn verify_signed(network: &str, kind: &str, signed: Signed) -> Result<Value> {
    body_check(&signed.body, network, &signed.public_key)?;
    let key = VerifyingKey::from_bytes(&hex_bytes::<32>(&signed.public_key)?)
        .map_err(|e| e.to_string())?;
    let signature = Signature::from_bytes(&hex_bytes::<64>(&signed.signature)?);
    key.verify_strict(&signature_bytes(kind, &signed.body)?, &signature)
        .map_err(|_| "contact signature invalid")?;
    Ok(signed.body)
}
pub(crate) fn verify_value(network: &str, kind: &str, value: &Value) -> Result<Value> {
    let signed: Signed = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    verify_signed(network, kind, signed)
}
fn execute(raw: &[u8]) -> Result<Value> {
    let value = crate::wallet_http::decode_unique_with_limit(raw, MAX_ABI)?;
    require(
        files::canonical_with_limit(&value, MAX_ABI)? == raw,
        "contact ABI noncanonical input",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    match request {
        Request::Config(request) => crate::contact_config::execute(request),
        Request::Exchange(request) => crate::contact_exchange::execute(request),
        Request::Transit(request) => crate::contact_transit::execute(request),
        Request::Tls(request) => crate::contact_tls::execute(request),
        Request::Info => Ok(
            serde_json::json!({"mesh":MESH,"active_storage":ACTIVE,"archive_storage":ARCHIVE,
            "receipt_scheduler":RECEIPT,"transit_scheduler":TRANSIT,"max_abi":MAX_ABI}),
        ),
        Request::Initialize {
            root,
            network,
            region,
            label,
        } => initialize(&root, network, region, label),
        Request::Inspect { identity, network } => public_identity(inspect(&identity, &network)?.0),
        Request::Sign {
            identity,
            network,
            public_key,
            kind,
            body,
        } => {
            let (identity, key) = inspect(&identity, &network)?;
            require(
                identity.public_key == public_key,
                "contact signer public pin differs",
            )?;
            body_check(&body, &network, &public_key)?;
            let signature = hex::encode(key.sign(&signature_bytes(&kind, &body)?).to_bytes());
            serde_json::to_value(Signed {
                body,
                public_key,
                signature,
            })
            .map_err(|e| e.to_string())
        }
        Request::Verify {
            network,
            kind,
            signed,
        } => verify_signed(&network, &kind, signed),
        Request::Schema {
            network,
            kind,
            limits,
            signed,
        } => crate::contact_schema::verify(&network, &kind, &signed, &limits),
    }
}

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}
fn output(raw: &[u8]) -> Vec<u8> {
    output_with(raw, || execute(raw))
}
pub(crate) fn output_with(
    raw: &[u8],
    work: impl FnOnce() -> Result<Value> + std::panic::UnwindSafe,
) -> Vec<u8> {
    let result = std::panic::catch_unwind(work)
        .unwrap_or_else(|_| Err("contact operation panic refused".into()));
    let (success, value, error) = match result {
        Ok(value) => (true, Some(value), None),
        Err(error) => (false, None, Some(error)),
    };
    let reply = serde_json::json!({"format":FORMAT,"implementation":crate::implementation().ok(),
        "request_sha256":Hash(Sha256::digest(raw).into()),"success":success,"value":value,"error":error,
        "ledger_authority":false,"durable_custody_qualified":false,"independent_security_qualified":false});
    files::canonical_with_limit(&reply, MAX_ABI).unwrap_or_else(|_| b"{}".to_vec())
}
/// Run one bounded transport operation; no private bytes cross the output ABI.
///
/// # Safety
/// Input must point to `len` readable bytes for this call, or be null with zero
/// length. The readable input must remain immutable for the entire call.
/// Callers must release the returned buffer exactly once with its exact
/// unchanged pointer and length using `rld_contact_crypto_free`.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_crypto(input: *const u8, len: usize) -> Buffer {
    let bytes = if input.is_null() || len == 0 || len > MAX_ABI {
        b"".as_slice()
    } else {
        unsafe { std::slice::from_raw_parts(input, len) }
    };
    buffer(output(bytes))
}
pub(crate) fn buffer(bytes: Vec<u8>) -> Buffer {
    let mut result = bytes.into_boxed_slice();
    let buffer = Buffer {
        data: result.as_mut_ptr(),
        len: result.len(),
    };
    std::mem::forget(result);
    buffer
}
/// Release one unchanged buffer returned by `rld_contact_crypto`.
///
/// # Safety
/// The buffer must be an original, live result from this exact library and must
/// not have been changed or freed. No other pointer may be supplied.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_crypto_free(buffer: Buffer) {
    if !buffer.data.is_null() {
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                buffer.data,
                buffer.len,
            )));
        }
    }
}
pub fn info() -> Result<Value> {
    Ok(serde_json::json!({"format":FORMAT,"implementation":crate::implementation()?}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domains_are_closed_and_hex_is_exact() {
        assert!(domain("bft-commit").is_err());
        assert!(domain("tcp-request").is_ok());
        assert!(hex_bytes::<32>(&"A".repeat(64)).is_err());
        assert!(hex_bytes::<32>(&"a".repeat(64)).is_ok());
        assert!(label_check("bad\nlabel").is_err());
    }
    #[test]
    fn malformed_ffi_request_is_bounded_and_has_no_authority() {
        let reply: Value = serde_json::from_slice(&output(b"{}")).unwrap();
        assert_eq!(reply["success"], false);
        assert_eq!(reply["ledger_authority"], false);
        assert_eq!(reply["durable_custody_qualified"], false);
    }
}
