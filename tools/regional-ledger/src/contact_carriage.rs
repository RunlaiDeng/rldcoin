//! Stateless first-carriage candidate planning; never custody or value authority.
use crate::{require, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::c_void;
const FORMAT: &str = "RLD-NATIVE-FIRST-CARRIAGE-V1";
const CODEC: &[u8] = b"RLD-FIRST-CARRIAGE-BYTES-V1\0";
const MAX_BYTES: usize = 64 * 1024;
const MAX_CHECKS: usize = 1056;
type Id = [u8; 32];
type Callback = unsafe extern "C" fn(*const u8, usize, *mut c_void) -> i32;
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .ok_or("carriage byte offset overflow")?;
        require(end <= self.raw.len(), "incomplete carriage bytes")?;
        let value = &self.raw[self.at..end];
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn id(&mut self) -> Result<Id> {
        self.take(32)?
            .try_into()
            .map_err(|_| "carriage identity length".into())
    }
    fn optional_id(&mut self) -> Result<Option<Id>> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.id()?)),
            _ => Err("carriage optional identity flag".into()),
        }
    }
    fn rows(&mut self, limit: usize) -> Result<Vec<Id>> {
        let count = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| "carriage count length")?,
        ) as usize;
        require(count <= limit, "carriage row capacity")?;
        let mut values = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let value = self.id()?;
            require(seen.insert(value), "duplicate carriage identity")?;
            values.push(value);
        }
        Ok(values)
    }
}
struct Eligibility {
    active: BTreeSet<Id>,
    receipted: BTreeSet<Id>,
    callback: Callback,
    context: *mut c_void,
    count: usize,
    digest: Sha256,
}
impl Eligibility {
    fn check(&mut self, id: &Id) -> Result<bool> {
        if !self.active.contains(id) || self.receipted.contains(id) {
            return Ok(false);
        }
        require(self.count < MAX_CHECKS, "carriage eligibility capacity")?;
        // The callback is scoped to this invocation and performs the caller's
        // original complete native checks in their original lazy order.
        let value = unsafe { (self.callback)(id.as_ptr(), id.len(), self.context) };
        require(
            value == 0 || value == 1,
            "carriage eligibility callback refused",
        )?;
        self.count += 1;
        self.digest.update(id);
        self.digest.update([value as u8]);
        Ok(value == 1)
    }
}
fn plan(raw: &[u8], callback: Callback, context: *mut c_void) -> Result<Value> {
    let mut reader = Reader { raw, at: 0 };
    require(reader.take(CODEC.len())? == CODEC, "carriage codec differs")?;
    let maximum = u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| "carriage limit length")?,
    ) as usize;
    let recent_limit = reader.byte()? as usize;
    require(
        maximum <= 256 && recent_limit <= 32,
        "carriage limits differ",
    )?;
    let network = reader.id()?;
    let node = reader.id()?;
    let peer = reader.id()?;
    require(node != peer, "carriage self peer")?;
    let active_rows = reader.rows(maximum)?;
    let receipted = reader.rows(maximum)?;
    let recent = reader.rows(recent_limit)?;
    let first_arrivals = reader.rows(maximum)?;
    let pending_rows = reader.rows(recent_limit)?;
    let prepared_rows = reader.rows(maximum)?;
    let old_arrivals = reader.rows(maximum)?;
    let observed = match reader.byte()? {
        0 => None,
        1 => Some(reader.rows(maximum)?),
        _ => return Err("carriage observed flag".into()),
    };
    let mut after = reader.optional_id()?;
    let mut next_kind = reader.byte()?;
    require(
        next_kind <= 1 && reader.at == raw.len(),
        "carriage kind or trailing bytes",
    )?;
    let pending_set: BTreeSet<_> = pending_rows.iter().copied().collect();
    let prepared_set: BTreeSet<_> = prepared_rows.iter().copied().collect();
    require(
        pending_set.is_disjoint(&prepared_set)
            && old_arrivals
                .iter()
                .all(|v| !pending_set.contains(v) && !prepared_set.contains(v)),
        "carriage waiting/prepared overlap",
    )?;
    let active: BTreeSet<_> = active_rows.into_iter().collect();
    let mut digest = Sha256::new();
    digest.update(CODEC);
    digest.update(b"ELIGIBILITY-V1\0");
    let mut eligibility = Eligibility {
        active,
        receipted: receipted.into_iter().collect(),
        callback,
        context,
        count: 0,
        digest,
    };
    let prepared: Vec<_> = prepared_rows
        .into_iter()
        .filter(|v| eligibility.active.contains(v))
        .collect();
    let mut pending = Vec::new();
    for id in pending_rows {
        if eligibility.check(&id)? {
            pending.push(id);
        }
    }
    let mut known: BTreeSet<_> = prepared.iter().chain(&pending).copied().collect();
    let mut arrivals = Vec::new();
    if let Some(observed) = observed {
        for id in old_arrivals {
            if !known.contains(&id) && eligibility.check(&id)? {
                arrivals.push(id);
            }
        }
        let seen: BTreeSet<_> = observed.into_iter().collect();
        let mut already: BTreeSet<_> = arrivals.iter().copied().collect();
        for id in first_arrivals {
            if !seen.contains(&id)
                && !known.contains(&id)
                && !already.contains(&id)
                && eligibility.check(&id)?
            {
                arrivals.push(id);
                already.insert(id);
            }
        }
    } else {
        for id in recent {
            if pending.len() == recent_limit {
                break;
            }
            if !known.contains(&id) && eligibility.check(&id)? {
                pending.push(id);
                known.insert(id);
            }
        }
    }
    require(arrivals.len() <= maximum, "first arrival backlog capacity")?;
    let reserved: BTreeSet<_> = arrivals.iter().copied().collect();
    let history: Vec<_> = eligibility
        .active
        .iter()
        .filter(|id| {
            !known.contains(*id) && !reserved.contains(*id) && !eligibility.receipted.contains(*id)
        })
        .copied()
        .collect();
    let start = if history.is_empty() {
        0
    } else {
        after.map_or(0, |v| {
            history.partition_point(|id| *id <= v) % history.len()
        })
    };
    let background: Vec<_> = history[start..]
        .iter()
        .chain(&history[..start])
        .copied()
        .collect();
    let mut streams = [arrivals.iter(), background.iter()];
    while pending.len() < recent_limit {
        let mut selected = None;
        for kind in [next_kind, 1 - next_kind] {
            for id in streams[kind as usize].by_ref() {
                if !known.contains(id) && eligibility.check(id)? {
                    selected = Some((kind, *id));
                    break;
                }
            }
            if selected.is_some() {
                break;
            }
        }
        let Some((kind, id)) = selected else {
            break;
        };
        pending.push(id);
        known.insert(id);
        if kind == 1 {
            after = Some(id);
        }
        next_kind = 1 - kind;
    }
    let ids = |values: Vec<Id>| values.into_iter().map(hex::encode).collect::<Vec<_>>();
    let remaining: Vec<_> = arrivals
        .iter()
        .filter(|id| !known.contains(*id))
        .copied()
        .collect();
    let plan = json!({"pending":ids(pending),"prepared":ids(prepared),"arrivals":ids(remaining),"observed":ids(eligibility.active.iter().copied().collect()),"history_after":after.map(hex::encode),"next_kind":next_kind});
    Ok(
        json!({"format":FORMAT,"network":hex::encode(network),"node":hex::encode(node),"peer":hex::encode(peer),"plan":plan,"eligibility_count":eligibility.count,"eligibility_sha256":hex::encode(eligibility.digest.finalize()),"candidate_only":true,"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
pub(crate) fn is_result(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.get("format").is_some_and(|f| f == FORMAT))
}
/// # Safety
/// Input is immutable and readable for this call. Callback/context stay live,
/// return normally, and may read only each scoped 32-byte identity. They must
/// implement the caller's complete current eligibility checks; no result is
/// ledger authority. Free the returned common buffer exactly once.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_first_carriage(
    input: *const u8,
    len: usize,
    callback: Option<Callback>,
    context: *mut c_void,
) -> crate::contact_crypto::Buffer {
    let valid = !input.is_null() && len > 0 && len <= MAX_BYTES;
    let raw = if valid {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    crate::contact_crypto::buffer(crate::contact_crypto::output_with(raw, || {
        require(valid, "carriage input byte bound")?;
        plan(
            raw,
            callback.ok_or("missing carriage eligibility callback")?,
            context,
        )
    }))
}
