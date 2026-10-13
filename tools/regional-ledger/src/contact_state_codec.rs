//! Operation-local exact shared-frame state codec; no authentication or ledger authority.
use crate::{
    contact_crypto::{buffer, output_with, Buffer},
    require, wallet_client as wire, Result,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
};

const FORMAT: &str = "RLD-NATIVE-CONTACT-STATE-CODEC-V1";
const STORAGE: &str = "RLD-CONTACT-ACTIVE-SHARED-FRAME-V1";
const FRAME: &str = "RLD-CONTACT-ACTIVE-FRAME-V1";
const MAX_STATE: usize = 64 * 1024 * 1024;
const MAX_MESSAGES: usize = 256;
const MAX_TRANSIT: usize = 20 * 1024 * 1024;
const MAX_FRAME_TEXT: usize = 2 * (4 * 1024 * 1024 + 4096);
const MAX_CONTROL: usize = 8192;
const MAX_CONTEXTS: usize = 8;
#[cfg(test)]
thread_local! {
    static ENCODING_TRACE: std::cell::RefCell<Option<Vec<Value>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn start_encoding_trace() {
    ENCODING_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
}
#[cfg(test)]
pub(crate) fn take_encoding_trace() -> Vec<Value> {
    ENCODING_TRACE.with(|trace| trace.borrow_mut().take().unwrap_or_default())
}
#[cfg(test)]
pub(crate) fn trace_encoding(phase: &'static str, raw: &[u8]) -> Result<()> {
    ENCODING_TRACE.with(|trace| -> Result<()> {
        if let Some(records) = trace.borrow_mut().as_mut() {
            require(records.len() < 8, "state encoding observation capacity")?;
            records.push(json!({"phase":phase,"size_bytes":raw.len(),"sha256":sha(raw)}));
        }
        Ok(())
    })
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_state: usize,
    max_messages: usize,
    max_transit: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.max_state <= MAX_STATE
                && self.max_messages <= MAX_MESSAGES
                && self.max_transit <= MAX_TRANSIT,
            "active state native limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Begin {
        token: String,
        limits: Limits,
        size_bytes: usize,
        sha256: String,
    },
    Transit {
        token: String,
        ident: String,
        size_bytes: usize,
        sha256: String,
    },
    Finish {
        token: String,
    },
    Abort {
        token: String,
    },
    Decode {
        network: String,
        node_id: String,
        limits: Limits,
        size_bytes: usize,
        sha256: String,
    },
    Usage,
}
fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| "active state object shape invalid".into())
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| format!("active state field missing: {name}"))
}
fn text(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| "active state string shape invalid".into())
}
fn exact(value: &Value, names: &[&str], message: &str) -> Result<()> {
    let map = object(value)?;
    require(
        map.len() == names.len() && names.iter().all(|name| map.contains_key(*name)),
        message,
    )
}
fn identifier(value: &str) -> Result<()> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "active state identifier invalid",
    )
}
fn token_check(value: &str) -> Result<()> {
    require(
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "active state codec token invalid",
    )
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn frame_check(value: &str) -> Result<()> {
    let padding = if value.ends_with("==") {
        2
    } else if value.ends_with('=') {
        1
    } else {
        0
    };
    require(
        value.len() <= MAX_FRAME_TEXT
            && value.as_bytes()[..value.len() - padding]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'),
        "active frame encoding/bound invalid",
    )
}
fn state_bounds(state: &Value, limits: &Limits) -> Result<(String, String)> {
    require(
        field(state, "active_storage")?.as_str() == Some(STORAGE),
        "active state storage binding differs; preserve legacy state",
    )?;
    let network = text(field(state, "network")?)?;
    let node = text(field(state, "node_id")?)?;
    identifier(network)?;
    identifier(node)?;
    require(
        object(field(state, "messages")?)?.len() <= limits.max_messages,
        "active state message capacity/schema invalid",
    )?;
    Ok((network.to_owned(), node.to_owned()))
}
fn transit_shape(value: &Value) -> Result<()> {
    exact(
        value,
        &["packet", "routing", "hops"],
        "active transit shape invalid",
    )?;
    object(field(value, "packet")?)?;
    object(field(field(value, "packet")?, "body")?)?;
    Ok(())
}
fn canonical(raw: &[u8], limit: usize) -> Result<Value> {
    require(raw.len() <= limit, "active state byte capacity exceeded")?;
    let value = crate::wallet_http::decode_unique_with_limit(raw, limit)?;
    require(
        wire::canonical_with_limit(&value, limit)? == raw,
        "noncanonical state JSON",
    )?;
    Ok(value)
}
fn bound_payload(raw: &[u8], size: usize, digest: &str, limit: usize) -> Result<()> {
    require(
        raw.len() <= limit && raw.len() == size && sha(raw) == digest,
        "active state codec payload binding differs",
    )
}
struct Pack {
    limits: Limits,
    image: Value,
    size: usize,
    failed: bool,
    closed: bool,
}
type Context = Arc<Mutex<Pack>>;
static CONTEXTS: OnceLock<Mutex<BTreeMap<String, Context>>> = OnceLock::new();
fn contexts() -> &'static Mutex<BTreeMap<String, Context>> {
    CONTEXTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn context(token: &str) -> Result<Context> {
    token_check(token)?;
    contexts()
        .lock()
        .map_err(|_| "active codec registry poisoned")?
        .get(token)
        .cloned()
        .ok_or_else(|| "active codec context absent".into())
}
fn begin(token: String, limits: Limits, raw: &[u8]) -> Result<Value> {
    token_check(&token)?;
    limits.check()?;
    let state = canonical(raw, limits.max_state)?;
    let (network, node) = state_bounds(&state, &limits)?;
    require(
        object(field(&state, "messages")?)?.is_empty(),
        "active codec initial messages must be empty",
    )?;
    let image =
        json!({"format":STORAGE,"network":network,"node_id":node,"state":state,"frames":{}});
    let size = wire::canonical_with_limit(&image, limits.max_state)?.len();
    let mut registry = contexts()
        .lock()
        .map_err(|_| "active codec registry poisoned")?;
    require(
        !registry.contains_key(&token),
        "active codec context already exists",
    )?;
    require(
        registry.len() < MAX_CONTEXTS,
        "active codec context capacity reached",
    )?;
    registry.insert(
        token.clone(),
        Arc::new(Mutex::new(Pack {
            limits,
            image,
            size,
            failed: false,
            closed: false,
        })),
    );
    Ok(json!({"format":FORMAT,"token":token,"begun":true,"ledger_authority":false}))
}
fn append(pack: &mut Pack, ident: &str, raw: &[u8]) -> Result<()> {
    identifier(ident)?;
    let records = object(field(field(&pack.image, "state")?, "messages")?)?;
    require(
        records.len() < pack.limits.max_messages && !records.contains_key(ident),
        "active state message capacity/schema invalid",
    )?;
    let mut transit = canonical(raw, pack.limits.max_transit)?;
    transit_shape(&transit)?;
    require(!raw.is_empty(), "active transit expanded bound exceeded")?;
    let frame = text(field(field(field(&transit, "packet")?, "body")?, "frame")?)?;
    frame_check(frame)?;
    let obj = json!({"format":FRAME,"network":field(&pack.image,"network")?,"node_id":field(&pack.image,"node_id")?,"frame":frame});
    let encoded = wire::canonical_with_limit(&obj, MAX_TRANSIT)?;
    let reference = sha(&encoded);
    let frames = object(field(&pack.image, "frames")?)?;
    let new_frame = match frames.get(&reference) {
        Some(previous) => {
            require(previous == &obj, "active frame collision")?;
            false
        }
        None => true,
    };
    let mut size = pack.size;
    if new_frame {
        size += 66 + 1 + encoded.len() + usize::from(!frames.is_empty());
    }
    transit["packet"]["body"]
        .as_object_mut()
        .ok_or("active frame metadata shape")?
        .remove("frame");
    let entry = json!({"transit":transit,"frame":reference,"expanded_size_bytes":raw.len(),"expanded_sha256":sha(raw)});
    size += 66
        + 1
        + wire::canonical_with_limit(&entry, pack.limits.max_state)?.len()
        + usize::from(!records.is_empty());
    require(
        size <= pack.limits.max_state,
        "durable state capacity reached; retain previous state",
    )?;
    // All fallible checks precede any operation-local state mutation.
    if new_frame {
        pack.image["frames"]
            .as_object_mut()
            .ok_or("active frame pool shape")?
            .insert(reference, obj);
    }
    pack.image["state"]["messages"]
        .as_object_mut()
        .ok_or("active record map shape")?
        .insert(ident.to_owned(), entry);
    pack.size = size;
    Ok(())
}
fn decode(raw: &[u8], network: &str, node: &str, limits: &Limits) -> Result<Value> {
    limits.check()?;
    identifier(network)?;
    identifier(node)?;
    let image = canonical(raw, limits.max_state)?;
    exact(
        &image,
        &["format", "network", "node_id", "state", "frames"],
        "active state image version differs; preserve legacy state",
    )?;
    require(
        field(&image, "format")?.as_str() == Some(STORAGE),
        "active state image version differs; preserve legacy state",
    )?;
    require(
        field(&image, "network")?.as_str() == Some(network)
            && field(&image, "node_id")?.as_str() == Some(node),
        "corrupt active state identity ownership differs",
    )?;
    let state = field(&image, "state")?;
    let (n, p) = state_bounds(state, limits)?;
    require(
        n == network && p == node,
        "active state metadata ownership differs",
    )?;
    let frames = object(field(&image, "frames")?)?;
    require(
        frames.len() <= limits.max_messages,
        "active frame pool capacity/schema invalid",
    )?;
    for (reference, obj) in frames {
        identifier(reference)?;
        exact(
            obj,
            &["format", "network", "node_id", "frame"],
            "active frame ownership/domain differs",
        )?;
        require(
            field(obj, "format")?.as_str() == Some(FRAME)
                && field(obj, "network")?.as_str() == Some(network)
                && field(obj, "node_id")?.as_str() == Some(node),
            "active frame ownership/domain differs",
        )?;
        frame_check(text(field(obj, "frame")?)?)?;
        require(
            sha(&wire::canonical_with_limit(obj, MAX_TRANSIT)?) == *reference,
            "active frame bytes differ",
        )?;
    }
    let mut referenced = BTreeSet::new();
    for (ident, entry) in object(field(state, "messages")?)? {
        identifier(ident)?;
        exact(
            entry,
            &["transit", "frame", "expanded_size_bytes", "expanded_sha256"],
            "active transit record differs",
        )?;
        let reference = text(field(entry, "frame")?)?;
        identifier(reference)?;
        let digest = text(field(entry, "expanded_sha256")?)?;
        identifier(digest)?;
        let obj = frames
            .get(reference)
            .ok_or("active frame reference missing")?;
        let size = field(entry, "expanded_size_bytes")?
            .as_u64()
            .ok_or("active transit expanded bound exceeded")?;
        require(
            size > 0 && size <= limits.max_transit as u64,
            "active transit expanded bound exceeded",
        )?;
        let mut expanded = field(entry, "transit")?.clone();
        transit_shape(&expanded)?;
        require(
            !object(field(field(&expanded, "packet")?, "body")?)?.contains_key("frame"),
            "active transit frame metadata differs",
        )?;
        expanded["packet"]["body"]
            .as_object_mut()
            .ok_or("active frame metadata shape")?
            .insert("frame".into(), field(obj, "frame")?.clone());
        let complete = wire::canonical_with_limit(&expanded, limits.max_transit)?;
        require(
            complete.len() as u64 == size,
            "active transit expanded size differs",
        )?;
        require(
            sha(&complete) == digest,
            "active transit complete bytes differ",
        )?;
        referenced.insert(reference.to_owned());
    }
    require(
        referenced.len() == frames.len(),
        "active frame orphan refused; preserve state",
    )?;
    // Return the bounded compact image, not a potentially multi-gigabyte expanded
    // serialized state. Caller assembles shared immutable strings, then fully
    // authenticates every original transit through ordinary validation.
    Ok(
        json!({"format":FORMAT,"image":image,"image_sha256":sha(raw),"ledger_authority":false,"authenticated":false}),
    )
}
fn finish(token: &str) -> Result<(Value, Vec<u8>)> {
    let ctx = context(token)?;
    let mut pack = ctx.lock().map_err(|_| "active codec context poisoned")?;
    require(
        !pack.failed && !pack.closed,
        "active codec context failed or closed",
    )?;
    let bytes = wire::canonical_with_limit(&pack.image, pack.limits.max_state)?;
    #[cfg(test)]
    trace_encoding("codec-finish", &bytes)?;
    require(bytes.len() == pack.size, "active state accounting differs")?;
    pack.closed = true;
    let image = std::mem::take(&mut pack.image);
    // Do not hold a registry lock while another operation's codec mutex is held.
    drop(pack);
    let mut registry = contexts()
        .lock()
        .map_err(|_| "active codec registry poisoned")?;
    if registry
        .get(token)
        .is_some_and(|current| Arc::ptr_eq(current, &ctx))
    {
        registry.remove(token);
    }
    Ok((image, bytes))
}

/// This invocation's complete canonical image after the original size checks.
/// The codec does not authenticate transport or grant ledger/custody authority.
pub(crate) fn finish_bytes(token: &str) -> Result<Vec<u8>> {
    finish(token).map(|(_, bytes)| bytes)
}

pub(crate) fn execute(control: &[u8], raw: &[u8]) -> Result<Value> {
    let request: Request =
        serde_json::from_value(canonical(control, MAX_CONTROL)?).map_err(|e| e.to_string())?;
    match request {
        Request::Info => {
            require(raw.is_empty(), "active codec unexpected payload")?;
            Ok(
                json!({"format":FORMAT,"storage":STORAGE,"frame":FRAME,"max_state":MAX_STATE,"max_messages":MAX_MESSAGES,"max_transit":MAX_TRANSIT,"max_contexts":MAX_CONTEXTS,"max_control":MAX_CONTROL,"ledger_authority":false}),
            )
        }
        Request::Begin {
            token,
            limits,
            size_bytes,
            sha256,
        } => {
            token_check(&token)?;
            // Refuse a retained token before any payload/schema error. The
            // failed caller must not mistake it for its own lost allocation.
            require(
                !contexts()
                    .lock()
                    .map_err(|_| "active codec registry poisoned")?
                    .contains_key(&token),
                "active codec context already exists",
            )?;
            bound_payload(raw, size_bytes, &sha256, limits.max_state)?;
            begin(token, limits, raw)
        }
        Request::Transit {
            token,
            ident,
            size_bytes,
            sha256,
        } => {
            let ctx = context(&token)?;
            let mut pack = ctx.lock().map_err(|_| "active codec context poisoned")?;
            require(
                !pack.failed && !pack.closed,
                "active codec context failed or closed",
            )?;
            match bound_payload(raw, size_bytes, &sha256, MAX_TRANSIT)
                .and_then(|()| append(&mut pack, &ident, raw))
            {
                Ok(()) => Ok(
                    json!({"format":FORMAT,"token":token,"retained":true,"ledger_authority":false}),
                ),
                Err(error) => {
                    pack.failed = true;
                    Err(error)
                }
            }
        }
        Request::Finish { token } => {
            require(raw.is_empty(), "active codec unexpected payload")?;
            let (image, bytes) = finish(&token)?;
            Ok(
                json!({"format":FORMAT,"image":image,"image_sha256":sha(&bytes),"ledger_authority":false,"authenticated":false}),
            )
        }
        Request::Abort { token } => {
            require(raw.is_empty(), "active codec unexpected payload")?;
            token_check(&token)?;
            let ctx = contexts()
                .lock()
                .map_err(|_| "active codec registry poisoned")?
                .remove(&token);
            if let Some(ctx) = ctx {
                ctx.lock()
                    .map_err(|_| "active codec context poisoned")?
                    .closed = true;
            }
            Ok(json!({"format":FORMAT,"token":token,"closed":true,"ledger_authority":false}))
        }
        Request::Decode {
            network,
            node_id,
            limits,
            size_bytes,
            sha256,
        } => {
            bound_payload(raw, size_bytes, &sha256, limits.max_state)?;
            decode(raw, &network, &node_id, &limits)
        }
        Request::Usage => {
            require(raw.is_empty(), "active codec unexpected payload")?;
            let count = contexts()
                .lock()
                .map_err(|_| "active codec registry poisoned")?
                .len();
            Ok(json!({"format":FORMAT,"contexts":count,"ledger_authority":false}))
        }
    }
}
/// Run a bounded, transient codec operation. No private key, ledger or witness
/// initializes authorization from decoded state.
///
/// # Safety
/// Control/payload pointers declare readable immutable bytes for the entire call.
/// Null payload is allowed only for zero length. Free the exact returned buffer
/// once with rld_contact_crypto_free. No control may supply executable addresses.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_state_codec(
    input: *const u8,
    len: usize,
    payload: *const u8,
    payload_len: usize,
) -> Buffer {
    let valid_control = len > 0 && len <= MAX_CONTROL && !input.is_null();
    let valid =
        valid_control && payload_len <= MAX_STATE && (payload_len == 0 || !payload.is_null());
    let control = if valid_control {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let raw = if valid && payload_len > 0 {
        unsafe { std::slice::from_raw_parts(payload, payload_len) }
    } else {
        &[]
    };
    buffer(output_with(control, || {
        require(valid, "active state codec ABI input invalid")?;
        execute(control, raw)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These minimal codec shapes are unauthenticated and grant no authority.
    fn transit() -> Vec<u8> {
        wire::canonical(&json!({"packet":{"body":{"frame":"YQ=="}},"routing":{},"hops":[]}))
            .unwrap()
    }
    fn call(control: Value, raw: &[u8]) -> Result<Value> {
        execute(&wire::canonical(&control)?, raw)
    }
    struct Session(String);
    impl Session {
        fn new(seed: usize) -> Self {
            let token = format!("c0dec0de{seed:024x}");
            let raw = wire::canonical(&json!({"active_storage":STORAGE,"network":"aa".repeat(32),
                "node_id":"bb".repeat(32),"messages":{}}))
            .unwrap();
            call(
                json!({"Begin":{"token":token,"limits":{"max_state":MAX_STATE,
                "max_messages":MAX_MESSAGES,"max_transit":MAX_TRANSIT},
                "size_bytes":raw.len(),"sha256":sha(&raw)}}),
                &raw,
            )
            .unwrap();
            Self(token)
        }
        fn append(&self, ident: &str, raw: &[u8]) -> Result<Value> {
            call(
                json!({"Transit":{"token":self.0,"ident":ident,
                "size_bytes":raw.len(),"sha256":sha(raw)}}),
                raw,
            )
        }
        fn abort(&self) {
            assert_eq!(
                call(json!({"Abort":{"token":self.0}}), &[]).unwrap()["closed"],
                true
            );
            assert!(context(&self.0).is_err());
        }
    }
    impl Drop for Session {
        fn drop(&mut self) {
            let _ = call(json!({"Abort":{"token":self.0}}), &[]);
        }
    }
    fn abi_finish(token: &str) -> Value {
        let control = wire::canonical(&json!({"Finish":{"token":token}})).unwrap();
        let result = unsafe {
            rld_contact_state_codec(control.as_ptr(), control.len(), std::ptr::null(), 0)
        };
        let raw = unsafe { std::slice::from_raw_parts(result.data, result.len) }.to_vec();
        unsafe { crate::contact_crypto::rld_contact_crypto_free(result) };
        serde_json::from_slice(&raw).unwrap()
    }
    fn refused_by_both(token: &str, message: &str) {
        assert!(finish_bytes(token).unwrap_err().contains(message));
        let reply = abi_finish(token);
        assert_eq!(reply["success"], false);
        assert!(reply["value"].is_null());
        assert!(reply["error"].as_str().unwrap().contains(message));
    }

    #[test]
    fn raw_and_abi_finish_keep_the_same_complete_shared_frame_image() {
        let raw_context = Session::new(1);
        let abi_context = Session::new(2);
        let transit = transit();
        for session in [&raw_context, &abi_context] {
            session.append(&"11".repeat(32), &transit).unwrap();
            session.append(&"22".repeat(32), &transit).unwrap();
        }
        let raw = finish_bytes(&raw_context.0).unwrap();
        let reply = abi_finish(&abi_context.0);
        assert_eq!(reply["success"], true);
        assert_eq!(reply["ledger_authority"], false);
        let external = &reply["value"];
        let image = &external["image"];
        assert_eq!(raw, wire::canonical_with_limit(image, MAX_STATE).unwrap());
        assert_eq!(object(&image["frames"]).unwrap().len(), 1);
        assert_eq!(object(&image["state"]["messages"]).unwrap().len(), 2);
        assert_eq!(
            external,
            &json!({"format":FORMAT,"image":image,
            "image_sha256":sha(&raw),"ledger_authority":false,"authenticated":false})
        );
        refused_by_both(&raw_context.0, "context absent");
        refused_by_both(&abi_context.0, "context absent");
    }

    #[test]
    fn failed_transit_and_duplicate_ident_refuse_both_finish_paths_until_abort() {
        let good = transit();
        let invalid =
            wire::canonical(&json!({"packet":{"body":{}},"routing":{},"hops":[]})).unwrap();
        for (seed, duplicate) in [(3, false), (4, true)] {
            let session = Session::new(seed);
            let ident = "33".repeat(32);
            if duplicate {
                session.append(&ident, &good).unwrap();
            }
            let ctx = context(&session.0).unwrap();
            let (image, size) = {
                let pack = ctx.lock().unwrap();
                (pack.image.clone(), pack.size)
            };
            assert!(session
                .append(&ident, if duplicate { &good } else { &invalid })
                .is_err());
            refused_by_both(&session.0, "context failed or closed");
            assert!(Arc::ptr_eq(&context(&session.0).unwrap(), &ctx));
            {
                let pack = ctx.lock().unwrap();
                assert!(pack.failed && !pack.closed);
                assert_eq!(pack.image, image);
                assert_eq!(pack.size, size);
            }
            session.abort();
        }
    }

    #[test]
    fn accounting_refusal_keeps_the_original_context_open_and_complete() {
        let session = Session::new(5);
        session.append(&"44".repeat(32), &transit()).unwrap();
        let ctx = context(&session.0).unwrap();
        let (image, size) = {
            let mut pack = ctx.lock().unwrap();
            let saved = (pack.image.clone(), pack.size);
            pack.size += 1; // Only this test's accounting witness is made inconsistent.
            saved
        };
        refused_by_both(&session.0, "active state accounting differs");
        assert!(Arc::ptr_eq(&context(&session.0).unwrap(), &ctx));
        {
            let mut pack = ctx.lock().unwrap();
            assert!(!pack.failed && !pack.closed);
            assert_eq!(pack.image, image);
            assert_eq!(pack.size, size + 1);
            pack.size = size;
        }
        let raw = finish_bytes(&session.0).unwrap();
        assert_eq!(raw.len(), size);
        assert_eq!(raw, wire::canonical_with_limit(&image, MAX_STATE).unwrap());
        refused_by_both(&session.0, "context absent");
    }
}
