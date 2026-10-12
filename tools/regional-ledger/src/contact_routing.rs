//! Pure candidate graph search; input adjacency is never ledger/route authority.
use crate::{contact_schema, require, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
const FORMAT: &str = "RLD-NATIVE-CONTACT-ROUTING-V1";
// Restricted candidate controls/results contain printable ASCII and integers.
// Verify the entire tree and existing Map order; all other values retain the
// original Python-compatible encoder, including floats, controls and Unicode.
pub(crate) fn canonical(value: &Value, limit: usize) -> Result<Vec<u8>> {
    fn eligible(value: &Value) -> bool {
        let printable = |s: &str| s.bytes().all(|b| (32..=126).contains(&b));
        match value {
            Value::Object(map) => {
                let mut previous: Option<&str> = None;
                map.iter().all(|(key, value)| {
                    let ordered = previous.is_none_or(|p| p < key.as_str());
                    previous = Some(key);
                    ordered && printable(key) && eligible(value)
                })
            }
            Value::Array(values) => values.iter().all(eligible),
            Value::String(s) => printable(s),
            Value::Number(n) => !n.is_f64(),
            Value::Bool(_) | Value::Null => true,
        }
    }
    if eligible(value) {
        let raw = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        require(raw.len() <= limit, "caller state byte bound")?;
        Ok(raw)
    } else {
        crate::wallet_client::canonical_with_limit(value, limit)
    }
}
pub(crate) fn is_result(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("format").is_some_and(|v| v == FORMAT))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    nodes: usize,
    contacts: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Search {
    network: String,
    node: String,
    destination: String,
    excluded: Vec<String>,
    first_hop: Option<String>,
    outgoing: Vec<String>,
    graph: BTreeMap<String, Vec<String>>,
    limits: Limits,
}
fn id(value: &str) -> Result<()> {
    contact_schema::hex(&json!(value))
}
fn search_path<K: Ord + Clone>(
    node: &K,
    destination: &K,
    graph: &BTreeMap<K, Vec<K>>,
    outgoing: BTreeSet<K>,
    mut seen: BTreeSet<K>,
    first: Option<&K>,
) -> Result<Option<Vec<K>>> {
    if node == destination {
        return Ok(Some(vec![node.clone()]));
    }
    seen.insert(node.clone());
    let mut frontier = VecDeque::from([vec![node.clone()]]);
    while let Some(path) = frontier.pop_front() {
        let Some(peers) = graph.get(path.last().ok_or("empty candidate path")?) else {
            continue;
        };
        for peer in peers {
            if seen.contains(peer)
                || (path.len() == 1
                    && (!outgoing.contains(peer) || first.is_some_and(|f| f != peer)))
            {
                continue;
            }
            let mut next = path.clone();
            next.push(peer.clone());
            require(next.len() <= 65, "native candidate path bound exceeded")?;
            if peer == destination {
                return Ok(Some(next));
            }
            seen.insert(peer.clone());
            require(
                seen.len() <= 2050 && frontier.len() < 1025,
                "native candidate frontier bound exceeded",
            )?;
            frontier.push_back(next);
        }
    }
    Ok(None)
}

const CODEC: &[u8] = b"RLD-CANDIDATE-ROUTE-BYTES-V1\0";
const MAX_BYTES: usize = 70 * 1024;
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(size)
            .ok_or("candidate byte offset overflow")?;
        require(end <= self.raw.len(), "incomplete candidate bytes")?;
        let result = &self.raw[self.at..end];
        self.at = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn identity(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| "candidate identity length differs".into())
    }
    fn identities(&mut self, count: usize) -> Result<Vec<[u8; 32]>> {
        (0..count).map(|_| self.identity()).collect()
    }
}
fn binary(raw: &[u8]) -> Result<Value> {
    require(
        !raw.is_empty() && raw.len() <= MAX_BYTES,
        "candidate byte bound",
    )?;
    let mut reader = Reader { raw, at: 0 };
    require(
        reader.take(CODEC.len())? == CODEC,
        "candidate codec differs",
    )?;
    let nodes = reader.byte()? as usize;
    let contacts = reader.byte()? as usize;
    require(
        nodes <= 64 && contacts <= 16,
        "native routing limits differ",
    )?;
    let network = reader.identity()?;
    let node = reader.identity()?;
    let destination = reader.identity()?;
    let flag = reader.byte()?;
    let first = match flag {
        0 => None,
        1 => Some(reader.identity()?),
        _ => return Err("candidate first-hop flag differs".into()),
    };
    let count = u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| "candidate exclusion length differs")?,
    ) as usize;
    require(count <= 1025, "native candidate exclusion capacity differs")?;
    let excluded = reader.identities(count)?;
    let count = reader.byte()? as usize;
    require(
        count <= contacts,
        "native candidate outgoing capacity differs",
    )?;
    let outgoing = reader.identities(count)?;
    let rows = reader.byte()? as usize;
    require(rows <= nodes, "native candidate graph capacity differs")?;
    let mut graph = BTreeMap::new();
    let mut previous = None;
    for _ in 0..rows {
        let key = reader.identity()?;
        require(
            previous.is_none_or(|p| p < key),
            "candidate graph duplicate/order differs",
        )?;
        previous = Some(key);
        let count = reader.byte()? as usize;
        require(count <= contacts, "native neighbor capacity differs")?;
        graph.insert(key, reader.identities(count)?);
    }
    require(reader.at == raw.len(), "candidate trailing bytes")?;
    let path = search_path(
        &node,
        &destination,
        &graph,
        outgoing.into_iter().collect(),
        excluded.into_iter().collect(),
        first.as_ref(),
    )?
    .map(|path| path.into_iter().map(hex::encode).collect::<Vec<_>>());
    Ok(
        json!({"format":FORMAT,"codec":"RLD-CANDIDATE-ROUTE-BYTES-V1","network":hex::encode(network),"node":hex::encode(node),
        "destination":hex::encode(destination),"path":path,"candidate_only":true,"labels_authenticated":false,
        "ledger_authority":false,"custody_acknowledgment":false}),
    )
}
/// # Safety
/// Input must be immutable/readable for this call. Oversized input is never
/// read. Release the exact returned buffer once through the common free entry.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_routing_bytes(
    input: *const u8,
    len: usize,
) -> crate::contact_crypto::Buffer {
    let valid = !input.is_null() && len > 0 && len <= MAX_BYTES;
    let raw = if valid {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    crate::contact_crypto::buffer(crate::contact_crypto::output_with(raw, || {
        require(valid, "candidate byte input bound")?;
        binary(raw)
    }))
}
pub(crate) fn execute(request: Search) -> Result<Value> {
    let Search {
        network,
        node,
        destination,
        excluded,
        first_hop,
        outgoing,
        graph,
        limits,
    } = request;
    require(
        limits.nodes <= 64 && limits.contacts <= 16,
        "native routing limits differ",
    )?;
    id(&network)?;
    id(&node)?;
    id(&destination)?;
    let path = if node == destination {
        Some(vec![node.clone()])
    } else {
        require(
            graph.len() <= limits.nodes
                && outgoing.len() <= limits.contacts
                && excluded.len() <= 1025,
            "native candidate graph capacity differs",
        )?;
        for (key, peers) in &graph {
            id(key)?;
            require(
                peers.len() <= limits.contacts,
                "native neighbor capacity differs",
            )?;
            for peer in peers {
                id(peer)?;
            }
        }
        for value in outgoing.iter().chain(excluded.iter()) {
            id(value)?;
        }
        if let Some(first) = &first_hop {
            id(first)?;
        }
        search_path(
            &node,
            &destination,
            &graph,
            outgoing.into_iter().collect(),
            excluded.into_iter().collect(),
            first_hop.as_ref(),
        )?
    };
    Ok(
        json!({"format":FORMAT,"network":network,"node":node,"destination":destination,"path":path,
        "candidate_only":true,"labels_authenticated":false,"ledger_authority":false,"custody_acknowledgment":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restricted_candidate_encoding_keeps_complete_existing_bytes_and_bounds() {
        let mut values = vec![
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(-1),
            json!(u64::MAX),
            json!(i64::MIN),
            json!({"z":["\\\"",true,1],"a":{"x":"printable"}}),
        ];
        for scalar in 0..=255 {
            let character = char::from_u32(scalar).expect("test scalar");
            values.push(
                json!({"value":character.to_string(),character.to_string():["nested",false,null]}),
            );
        }
        for text in ["0.0", "-0.0", "1.25", "1e-6", "1e20", "-1e100"] {
            values.push(serde_json::from_str::<Value>(text).expect("test float"));
        }
        values.push(json!({"unicode":"中文🙂","control":"\u{7f}\n\0","array":[1,{"key":"value"}]}));
        for value in values {
            let expected =
                crate::wallet_client::canonical_with_limit(&value, 8192).expect("original encoder");
            assert_eq!(
                canonical(&value, 8192).expect("candidate encoder"),
                expected
            );
            assert_eq!(
                canonical(&value, expected.len()).expect("exact bound"),
                expected
            );
            assert!(canonical(&value, expected.len() - 1).is_err());
        }
    }
}
