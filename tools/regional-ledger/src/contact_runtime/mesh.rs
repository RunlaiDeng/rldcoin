use super::*;
use crate::Hash;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const ACTIVE: &str = "RLD-CONTACT-ACTIVE-SHARED-FRAME-V1";
const MAX_MESSAGES: usize = 256;
const MAX_ARCHIVE_FILES: usize = 4096;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(test)]
thread_local! {
    static PARALLEL_COLD_FIXTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct State {
    format: String,
    active_storage: String,
    network: String,
    node_id: String,
    adverts: BTreeMap<String, Value>,
    messages: BTreeMap<String, Value>,
    receipts: BTreeMap<String, Value>,
    // Immutable complete custody objects. Only completed packets leave active state.
    archives: BTreeMap<String, String>,
    cursor: u64,
    arrivals: Vec<String>,
    first_carried: BTreeMap<String, Vec<String>>,
    transit_cursors: BTreeMap<String, String>,
    receipt_cursors: BTreeMap<String, String>,
    peer_inventory: BTreeMap<String, Value>,
}

impl State {
    fn exact(&self, other: &Self) -> bool {
        fn value(left: &Value, right: &Value) -> bool {
            match (left, right) {
                (Value::Number(a), Value::Number(b)) => a.to_string() == b.to_string(),
                (Value::Array(a), Value::Array(b)) => {
                    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| value(a, b))
                }
                (Value::Object(a), Value::Object(b)) => {
                    a.len() == b.len()
                        && a.iter()
                            .zip(b)
                            .all(|((ak, av), (bk, bv))| ak == bk && value(av, bv))
                }
                _ => left == right,
            }
        }
        // Typed equality covers every metadata field. Compare every complete
        // Value too: JSON numeric equality must not erase signed zero/type bytes.
        self == other
            && [
                &self.adverts,
                &self.messages,
                &self.receipts,
                &self.peer_inventory,
            ]
            .into_iter()
            .zip([
                &other.adverts,
                &other.messages,
                &other.receipts,
                &other.peer_inventory,
            ])
            .all(|(a, b)| {
                a.iter()
                    .zip(b)
                    .all(|((ak, av), (bk, bv))| ak == bk && value(av, bv))
            })
    }
}

pub struct Node {
    pub root: PathBuf,
    pub network: String,
    pub id: String,
    pub region: String,
    pub contacts: BTreeMap<String, Value>,
    identity: Value,
    state: State,
    // One complete image under this mesh lease. Install only after complete
    // cold validation or successful durable publication; never serialize it.
    retained_image: Option<Vec<u8>>,
    _lock: Lease,
}

pub fn initialize(root: &Path, network: &str, region: &str, label: &str) -> Result<Value> {
    let root = directory(root)?;
    let _lock = Lease::acquire(&root, "Startup")?;
    crypto(json!({"Initialize":{"root":root,"network":network,"region":region,"label":label}}))
}

fn codec(control: Value, raw: &[u8]) -> Result<Value> {
    crate::contact_state_codec::execute(&bytes(&control)?, raw)
}
fn payload(raw: &[u8]) -> Value {
    json!({"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw))})
}
fn codec_limits() -> Value {
    json!({"max_state":STATE_LIMIT,"max_messages":256,"max_transit":EXCHANGE_LIMIT})
}
fn codec_request(mode: &str, mut fields: Value, raw: &[u8]) -> Result<Value> {
    let object = fields.as_object_mut().ok_or("codec request object")?;
    object.extend(
        payload(raw)
            .as_object()
            .ok_or("codec payload object")?
            .clone(),
    );
    codec(json!({mode:fields}), raw)
}
fn identifier(value: &str) -> Result<()> {
    crate::contact_crypto::hex_bytes::<32>(value).map(|_| ())
}
fn receipt_matches(receipt: &Value, packet: &Value, route: &Value) -> Result<()> {
    require(
        receipt["body"]["node_id"] == packet["destination"]
            && receipt["body"]["frame_id"] == route["frame_id"]
            && receipt["body"]["routing"]["body"] == *route,
        "receipt does not bind original destination/frame/route",
    )
}

impl Node {
    #[cfg(test)]
    fn open_parallel_fixture(config: &Value) -> Result<Self> {
        struct Reset(bool);
        impl Drop for Reset {
            fn drop(&mut self) {
                PARALLEL_COLD_FIXTURE.with(|flag| flag.set(self.0));
            }
        }
        let previous = PARALLEL_COLD_FIXTURE.with(|flag| flag.replace(true));
        let _reset = Reset(previous);
        Self::open(config)
    }

    #[cfg(test)]
    fn validate_archives_parallel_fixture(&self) -> Result<()> {
        let entries = self.state.archives.iter().collect::<Vec<_>>();
        let (left, right) = entries.split_at(entries.len().div_ceil(2));
        let check = |entries: &[(&String, &String)]| -> Result<()> {
            for (id, object) in entries {
                self.archive(id, object)?;
            }
            Ok(())
        };
        // One additional scoped worker; both halves finish before release.
        // Every archive still executes the exact original complete kernel.
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| check(left));
            let right_result = check(right);
            let left_result = worker.join().map_err(|_| "cold archive worker panicked")?;
            left_result?;
            right_result
        })
    }

    pub fn open(config: &Value) -> Result<Self> {
        crypto(
            json!({"Config":{"Header":{"keys":config.as_object().ok_or("contact config object")?.keys().collect::<Vec<_>>(),"version":config["format"]}}}),
        )?;
        let network = config["network"]
            .as_str()
            .ok_or("contact network string")?
            .to_owned();
        identifier(&network)?;
        let root = directory(Path::new(
            config["state"].as_str().ok_or("contact root path")?,
        ))?;
        let lock = Lease::acquire(&root, "Mesh")?;
        let identity = crypto(
            json!({"Inspect":{"identity":root.join("identity.private.json"),"network":network}}),
        )?;
        let id = identity["node_id"]
            .as_str()
            .ok_or("native contact identity")?
            .to_owned();
        let region = identity["region"]
            .as_str()
            .ok_or("native contact region")?
            .to_owned();
        let rows = config["contacts"]
            .as_array()
            .ok_or("contact list required")?;
        require(rows.len() <= 16, "contact capacity reached")?;
        let mut contacts = BTreeMap::new();
        for contact in rows {
            let resolved = crypto(
                json!({"Config":{"Resolve":{"contact":contact,"node":id,"seen":contacts.keys().collect::<Vec<_>>()}}}),
            )?;
            let mut normalized = resolved["value"]["contact"].clone();
            let peer = contact["peer"]
                .as_str()
                .ok_or("contact peer required")?
                .to_owned();
            for field in ["inbox", "outbox"] {
                if let Some(path) = contact[field].as_str() {
                    normalized[field] = json!(directory(Path::new(path))?);
                }
            }
            contacts.insert(peer, normalized);
        }
        let paths: Vec<_> = contacts
            .values()
            .flat_map(|c| {
                ["inbox", "outbox"]
                    .into_iter()
                    .filter_map(move |k| c[k].as_str())
            })
            .collect();
        crypto(json!({"Config":{"Spools":{"paths":paths,"pair":false}}}))?;
        directory(&root.join("archive"))?;
        // Refuse legacy Python state before any creation or replacement.
        require(
            !root.join("mesh-state.json").exists() && !root.join("mesh-state.json").is_symlink(),
            "legacy contact state requires a fresh Rust fixture directory; no conversion",
        )?;
        let path = root.join("native-mesh-state.json");
        let (state, retained_image) = if fs::symlink_metadata(&path).is_ok() {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            let raw = files::private_read_with_limit(&path, STATE_LIMIT)?;
            let decoded = codec_request(
                "Decode",
                json!({"network":network,"node_id":id,"limits":codec_limits()}),
                &raw,
            )?;
            let mut expanded = decoded["image"]["state"].clone();
            for entry in expanded["messages"]
                .as_object_mut()
                .ok_or("native active messages")?
                .values_mut()
            {
                let mut transit = entry["transit"].clone();
                let key = entry["frame"].as_str().ok_or("native frame reference")?;
                transit["packet"]["body"]["frame"] =
                    decoded["image"]["frames"][key]["frame"].clone();
                *entry = transit;
            }
            let state = serde_json::from_value(expanded).map_err(|e| e.to_string())?;
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-decode-expand", started)?;
            (state, Some(raw))
        } else {
            (
                State {
                    format: FORMAT.into(),
                    active_storage: ACTIVE.into(),
                    network: network.clone(),
                    node_id: id.clone(),
                    adverts: BTreeMap::new(),
                    messages: BTreeMap::new(),
                    receipts: BTreeMap::new(),
                    archives: BTreeMap::new(),
                    cursor: 0,
                    arrivals: Vec::new(),
                    first_carried: BTreeMap::new(),
                    transit_cursors: BTreeMap::new(),
                    receipt_cursors: BTreeMap::new(),
                    peer_inventory: BTreeMap::new(),
                },
                None,
            )
        };
        let mut node = Self {
            root,
            network,
            id,
            region,
            contacts,
            identity,
            state,
            retained_image: None,
            _lock: lock,
        };
        node.validate()?;
        node.retained_image = retained_image;
        let neighbors: Vec<_> = node
            .contacts
            .iter()
            .filter(|(_, c)| c.get("host").is_some() || c.get("outbox").is_some())
            .map(|(p, _)| p.clone())
            .collect();
        let old = node.state.adverts.get(&node.id);
        let mut body = json!({"format":MESH,"network":node.network,"node_id":node.id,"region":node.region,
            "label":node.identity["label"],"sequence":old.map_or(1,|v|v["body"]["sequence"].as_u64().unwrap_or(0)),"neighbors":neighbors});
        if old.is_some_and(|v| v["body"] != body) {
            body["sequence"] = json!(body["sequence"]
                .as_u64()
                .ok_or("advert sequence")?
                .checked_add(1)
                .ok_or("advert sequence exhausted")?);
        }
        let advert = node.sign("advert", body)?;
        schema(&advert, &node.network, "advert")?;
        let changed = node.state.adverts.get(&node.id) != Some(&advert);
        node.state.adverts.insert(node.id.clone(), advert);
        if changed {
            node.save()?;
        }
        Ok(node)
    }

    pub(crate) fn sign(&self, kind: &str, body: Value) -> Result<Value> {
        crypto(
            json!({"Sign":{"identity":self.root.join("identity.private.json"),"network":self.network,
            "public_key":self.identity["public_key"],"kind":kind,"body":body}}),
        )
    }

    fn validate(&self) -> Result<()> {
        let s = &self.state;
        require(
            s.format == FORMAT
                && s.active_storage == ACTIVE
                && s.network == self.network
                && s.node_id == self.id,
            "Rust contact state identity/version differs",
        )?;
        require(
            s.adverts.len() <= 64
                && s.messages.len() <= 256
                && s.receipts.len() <= 256
                && s.archives.len() <= 4096
                && s.cursor <= i64::MAX as u64
                && s.transit_cursors.len() <= 16
                && s.receipt_cursors.len() <= 16
                && s.peer_inventory.len() <= 16,
            "Rust contact state capacity",
        )?;
        require(
            s.arrivals.len() == s.messages.len()
                && s.arrivals.iter().collect::<std::collections::BTreeSet<_>>()
                    == s.messages.keys().collect()
                && s.first_carried.len() <= 16,
            "arrival scheduling identity/count bound",
        )?;
        for (peer, ids) in &s.first_carried {
            identifier(peer)?;
            require(
                ids.len() <= 256
                    && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len(),
                "first carriage scheduling capacity",
            )?;
            for id in ids {
                identifier(id)?;
            }
        }
        for (id, advert) in &s.adverts {
            let checked = schema(advert, &self.network, "advert")?;
            require(checked["body"]["node_id"] == *id, "advert index identity")?;
        }
        for (id, t) in &s.messages {
            let verified = transit(t, &self.network, Value::Null, Value::Null)?;
            require(
                digest(&t["packet"])? == *id
                    && verified["visited"].as_array().and_then(|v| v.last())
                        == Some(&json!(self.id)),
                "retained transit identity/custodian",
            )?;
        }
        for (id, r) in &s.receipts {
            let checked = schema(r, &self.network, "receipt")?;
            require(
                checked["body"]["packet_id"] == *id,
                "receipt index identity",
            )?;
            if let Some(t) = s.messages.get(id) {
                receipt_matches(r, &t["packet"]["body"], &t["routing"]["body"])?;
            }
        }
        for (peer, value) in &s.peer_inventory {
            let checked = schema(value, &self.network, "inventory")?;
            require(
                checked["body"]["node_id"] == *peer,
                "inventory index identity",
            )?;
        }
        for map in [&s.transit_cursors, &s.receipt_cursors] {
            for (peer, cursor) in map {
                identifier(peer)?;
                identifier(cursor)?;
            }
        }
        self.archive_inventory()?;
        #[cfg(test)]
        if PARALLEL_COLD_FIXTURE.with(std::cell::Cell::get) {
            return self.validate_archives_parallel_fixture();
        }
        for (id, object) in &s.archives {
            self.archive(id, object)?;
        }
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        // A failed publication cannot leave a reusable image paired with
        // uncertain live metadata, even if its caller continues using this Node.
        self.retained_image = None;
        #[cfg(test)]
        let save_started = super::service::monotonic()?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let token = random()?[..32].to_owned();
        let mut meta = serde_json::to_value(&self.state).map_err(|e| e.to_string())?;
        meta["messages"] = json!({});
        let raw = bytes(&meta)?;
        #[cfg(test)]
        super::service::trace_subwork("mesh-state-metadata", started)?;
        #[cfg(test)]
        let started = super::service::monotonic()?;
        codec_request(
            "Begin",
            json!({"token":token,"limits":codec_limits()}),
            &raw,
        )?;
        #[cfg(test)]
        super::service::trace_subwork("mesh-state-codec-begin", started)?;
        let operation: Result<Vec<u8>> = (|| {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            for (id, t) in &self.state.messages {
                codec_request("Transit", json!({"token":token,"ident":id}), &bytes(t)?)?;
            }
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-encode-transits", started)?;
            #[cfg(test)]
            let started = super::service::monotonic()?;
            let raw = crate::contact_state_codec::finish_bytes(&token)?;
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-encode-finish", started)?;
            #[cfg(test)]
            let started = super::service::monotonic()?;
            atomic_bytes(&self.root.join("native-mesh-state.json"), &raw, STATE_LIMIT)?;
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-durable-write", started)?;
            Ok(raw)
        })();
        #[cfg(test)]
        let started = super::service::monotonic()?;
        let cleanup = codec(json!({"Abort":{"token":token}}), &[]);
        #[cfg(test)]
        super::service::trace_subwork("mesh-state-codec-cleanup", started)?;
        let raw = operation?;
        cleanup?;
        self.retained_image = Some(raw);
        #[cfg(test)]
        super::service::trace_subwork("mesh-state-save-complete", save_started)?;
        Ok(())
    }

    fn archive_inventory(&self) -> Result<(usize, u64)> {
        let mut count = 0usize;
        let mut size = 0u64;
        for item in fs::read_dir(self.root.join("archive")).map_err(|e| e.to_string())? {
            let item = item.map_err(|e| e.to_string())?;
            let meta = fs::symlink_metadata(item.path()).map_err(|e| e.to_string())?;
            require(
                meta.is_file() && !meta.file_type().is_symlink(),
                "archive contains unsafe object",
            )?;
            count = count.checked_add(1).ok_or("archive inventory overflow")?;
            size = size
                .checked_add(meta.len())
                .ok_or("archive byte overflow")?;
            require(
                count <= MAX_ARCHIVE_FILES && size <= MAX_ARCHIVE_BYTES,
                "archive capacity reached; preserve all objects",
            )?;
        }
        Ok((count, size))
    }

    fn archive(&self, id: &str, object: &str) -> Result<Value> {
        #[cfg(test)]
        let started = super::service::monotonic()?;
        identifier(id)?;
        identifier(object)?;
        let (value, raw) = read_with_bytes(
            &self.root.join("archive").join(format!("{object}.json")),
            STATE_LIMIT,
        )?;
        // This exact read already uniquely decoded and canonically checked all
        // bytes. Hash the same complete bytes once; no hash grants authority.
        let whole_digest = hex::encode(Sha256::digest(&raw));
        drop(raw);
        require(
            whole_digest == object
                && value["format"] == FORMAT
                && value["network"] == self.network
                && value["node_id"] == self.id
                && value["packet_id"] == id,
            "archive complete byte/domain binding",
        )?;
        #[cfg(test)]
        super::service::trace_subwork("mesh-archive-read-bind", started)?;
        let receipt = &value["receipt"];
        let checked = schema(receipt, &self.network, "receipt")?;
        require(
            checked["body"]["packet_id"] == id,
            "archive receipt packet binding",
        )?;
        if !value["transit"].is_null() {
            let t = &value["transit"];
            let checked = transit(t, &self.network, Value::Null, Value::Null)?;
            require(
                digest(&t["packet"])? == id
                    && checked["visited"].as_array().and_then(|v| v.last())
                        == Some(&json!(self.id)),
                "archive transit custodian",
            )?;
            receipt_matches(receipt, &t["packet"]["body"], &t["routing"]["body"])?;
        }
        Ok(value)
    }

    pub fn received_frames(&self) -> Result<Vec<(String, Vec<u8>)>> {
        self.frame_page(None, 4)
    }

    pub(crate) fn frame_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        require(limit <= 4, "native receive page capacity")?;
        self.frame_page_selected(after, limit, &[])
    }

    pub(crate) fn frame_page_selected(
        &self,
        after: Option<&str>,
        limit: usize,
        seen: &[String],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        require(
            limit <= 4 && seen.len() <= 512,
            "native receive selection bound",
        )?;
        let mut ids: Vec<_> = self
            .state
            .messages
            .keys()
            .chain(self.state.archives.keys())
            .cloned()
            .collect();
        ids.sort();
        ids.dedup();
        if let Some(after) = after {
            let offset = ids.partition_point(|id| id.as_str() <= after);
            ids.rotate_left(offset);
        }
        let mut excluded = BTreeSet::new();
        if !seen.is_empty() {
            let active = self
                .state
                .arrivals
                .iter()
                .filter(|id| {
                    !seen.contains(id)
                        && self.state.messages[*id]["packet"]["body"]["destination"] == self.id
                })
                .take(2)
                .cloned()
                .collect::<Vec<_>>();
            let mut archived = Vec::new();
            for (id, object) in &self.state.archives {
                if seen.contains(id) {
                    continue;
                }
                let archive = self.archive(id, object)?;
                if archive["transit"]["packet"]["body"]["destination"] == self.id {
                    archived.push(id.clone());
                    if archived.len() == 2 {
                        break;
                    }
                } else if !self.state.messages.contains_key(id) {
                    require(
                        excluded.len() < MAX_ARCHIVE_FILES,
                        "receive page exclusion bound",
                    )?;
                    excluded.insert(id.clone());
                }
            }
            // Completion archives transport custody, not Native processing.
            // Share the two first-processing slots between active and archived
            // unseen destination frames; retain two ordinary historical slots.
            let first = (0..2)
                .flat_map(|i| [active.get(i), archived.get(i)])
                .flatten()
                .take(2)
                .cloned()
                .collect::<Vec<_>>();
            let mut selected = first.clone();
            selected.extend(ids.into_iter().filter(|id| !first.contains(id)));
            ids = selected;
        }
        let mut result = Vec::new();
        for id in ids {
            if result.len() == limit {
                break;
            }
            // This operation already authenticated these complete archives
            // and found no local frame. Only their immutable identities live
            // until this call ends; later calls and cold opens check again.
            if excluded.contains(&id) {
                continue;
            }
            let archived;
            let t = if let Some(t) = self.state.messages.get(&id) {
                t
            } else {
                archived =
                    self.archive(&id, self.state.archives.get(&id).ok_or("archive index")?)?;
                &archived["transit"]
            };
            if t["packet"]["body"]["destination"] == self.id {
                transit(t, &self.network, Value::Null, Value::Null)?;
                result.push((
                    id,
                    STANDARD
                        .decode(
                            t["packet"]["body"]["frame"]
                                .as_str()
                                .ok_or("retained frame string")?,
                        )
                        .map_err(|e| e.to_string())?,
                ));
            }
        }
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn originated_frame(
        &self,
        frame: Hash,
        destination: &str,
    ) -> Result<Option<String>> {
        identifier(destination)?;
        // A fully authenticated local packet proves first origination only.
        // It grants no peer custody, receipt, Native acceptance or finality.
        for (id, t) in &self.state.messages {
            if t["packet"]["body"]["node_id"] == self.id
                && t["packet"]["body"]["destination"] == destination
                && t["routing"]["body"]["frame_id"] == frame.to_hex()
            {
                return Ok(Some(id.clone()));
            }
        }
        for (id, object) in &self.state.archives {
            let a = self.archive(id, object)?;
            let t = &a["transit"];
            if t["packet"]["body"]["node_id"] == self.id
                && t["packet"]["body"]["destination"] == destination
                && t["routing"]["body"]["frame_id"] == frame.to_hex()
            {
                return Ok(Some(id.clone()));
            }
        }
        Ok(None)
    }

    pub(crate) fn originated_frames(&self) -> Result<BTreeSet<(Hash, String)>> {
        let mut frames = BTreeSet::new();
        let mut include = |transit: &Value| -> Result<()> {
            if transit["packet"]["body"]["node_id"] == self.id {
                let destination = transit["packet"]["body"]["destination"]
                    .as_str()
                    .ok_or("originated packet destination")?;
                identifier(destination)?;
                let frame = Hash::from_hex(
                    transit["routing"]["body"]["frame_id"]
                        .as_str()
                        .ok_or("originated packet frame identity")?,
                )
                .map_err(|e| format!("{e:?}"))?;
                frames.insert((frame, destination.to_owned()));
            }
            Ok(())
        };
        for transit in self.state.messages.values() {
            include(transit)?;
        }
        for (id, object) in &self.state.archives {
            include(&self.archive(id, object)?["transit"])?;
        }
        // One bounded, call-local scheduling observation avoids re-reading
        // every complete archive for each historical owner submission.
        Ok(frames)
    }

    pub(crate) fn prioritize_originated_packets(&mut self, ids: &[String]) -> Result<()> {
        let requested = ids.iter().collect::<std::collections::BTreeSet<_>>();
        require(
            ids.len() <= MAX_MESSAGES && requested.len() == ids.len(),
            "originated scheduling identity/count bound",
        )?;
        let mut first = Vec::new();
        for id in ids {
            if let Some(t) = self.state.messages.get(id) {
                require(
                    t["packet"]["body"]["node_id"] == self.id,
                    "scheduling priority requires a locally originated packet",
                )?;
                first.push(id.clone());
            } else {
                let object = self
                    .state
                    .archives
                    .get(id)
                    .ok_or("missing originated scheduling packet")?;
                require(
                    self.archive(id, object)?["transit"]["packet"]["body"]["node_id"] == self.id,
                    "archived scheduling packet was not locally originated",
                )?;
            }
        }
        first.extend(
            self.state
                .arrivals
                .iter()
                .filter(|id| !requested.contains(id))
                .cloned(),
        );
        if first == self.state.arrivals {
            return Ok(());
        }
        // Only reorder existing complete custody. The ordinary two-first and
        // two-history send slots, signatures, routes and receipt checks remain.
        // This scheduling metadata grants no Native or signing authority.
        let old = std::mem::replace(&mut self.state.arrivals, first);
        if let Err(error) = self.save() {
            self.state.arrivals = old;
            return Err(error);
        }
        Ok(())
    }

    pub fn enqueue(&mut self, raw: &[u8], destination: &str) -> Result<String> {
        self.enqueue_destinations(raw, &[destination.to_owned()])?
            .into_iter()
            .next()
            .ok_or("missing single-destination packet".into())
    }

    pub(crate) fn enqueue_destinations(
        &mut self,
        raw: &[u8],
        destinations: &[String],
    ) -> Result<Vec<String>> {
        self.enqueue_frame_batch(&[raw], destinations)?
            .into_iter()
            .next()
            .ok_or("missing single-frame destination batch".into())
    }

    pub(crate) fn enqueue_frame_batch(
        &mut self,
        raws: &[&[u8]],
        destinations: &[String],
    ) -> Result<Vec<Vec<String>>> {
        require(
            !raws.is_empty() && raws.len() <= 4,
            "outgoing frame batch bound",
        )?;
        let wanted = destinations
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        require(
            !destinations.is_empty()
                && destinations.len() <= 16
                && wanted.len() == destinations.len(),
            "outgoing destination batch identity/count bound",
        )?;
        for destination in destinations {
            identifier(destination)?;
        }
        let mut frames = Vec::new();
        let mut unique = BTreeSet::new();
        for raw in raws {
            let (frame, _) = crate::contact_frame::inspect_bytes(
                raw,
                None,
                None,
                crate::contact::MAX_PAYLOAD,
                crate::contact::MAX_FRAME,
            )?;
            require(
                unique.insert(frame.message_id.to_hex()),
                "duplicate outgoing frame batch identity",
            )?;
            frames.push(frame);
        }
        // One call-local lookup of complete authenticated custody, with no
        // retained proof/cache. Every later call checks its exact input again.
        let mut found = BTreeMap::<(String, String), String>::new();
        let include = |id: &str, t: &Value| {
            if t["packet"]["body"]["node_id"] == self.id
                && t["routing"]["body"]["frame_id"]
                    .as_str()
                    .is_some_and(|id| unique.contains(id))
            {
                if let Some(destination) = t["packet"]["body"]["destination"].as_str() {
                    if destinations.iter().any(|d| d == destination) {
                        return Some((
                            (
                                t["routing"]["body"]["frame_id"].as_str()?.to_owned(),
                                destination.to_owned(),
                            ),
                            id.to_owned(),
                        ));
                    }
                }
            }
            None
        };
        for (id, t) in &self.state.messages {
            if let Some((destination, id)) = include(id, t) {
                found.entry(destination).or_insert(id);
            }
        }
        for (id, object) in &self.state.archives {
            if found.len() == frames.len() * destinations.len() {
                break;
            }
            let archive = self.archive(id, object)?;
            if let Some((destination, id)) = include(id, &archive["transit"]) {
                found.entry(destination).or_insert(id);
            }
        }
        require(
            self.state.messages.len() + frames.len() * destinations.len() - found.len()
                <= MAX_MESSAGES,
            "active packet capacity reached; retain old evidence",
        )?;
        let mut batches = Vec::new();
        let mut pending = Vec::new();
        for (frame, raw) in frames.iter().zip(raws) {
            let mut ids = Vec::new();
            for destination in destinations {
                if let Some(id) = found.get(&(frame.message_id.to_hex(), destination.clone())) {
                    ids.push(id.clone());
                    continue;
                }
                let packet = self.sign("packet",json!({"format":MESH,"network":self.network,"node_id":self.id,
            "destination":destination,"nonce":random()?,"hop_limit":16,"frame":STANDARD.encode(raw)}))?;
                let id = digest(&packet)?;
                let routing = self.sign(
                    "receipt-route",
                    json!({"format":MESH,"network":self.network,"node_id":self.id,
            "packet_id":id,"destination":destination,"frame_id":frame.message_id}),
                )?;
                let t = json!({"packet":packet,"routing":routing,"hops":[]});
                transit(&t, &self.network, Value::Null, Value::Null)?;
                ids.push(id.clone());
                pending.push((id, t));
            }
            batches.push(ids);
        }
        if !pending.is_empty() {
            for (id, t) in pending {
                self.retained_image = None;
                self.state.messages.insert(id.clone(), t);
                self.state.arrivals.push(id);
            }
            // The whole bounded typed image is durable before any batch result.
            self.save()?;
        }
        Ok(batches)
    }

    fn route(&self, destination: &str, excluded: Vec<String>, first: &str) -> Result<bool> {
        let graph: BTreeMap<_, _> = self
            .state
            .adverts
            .iter()
            .map(|(id, a)| (id.clone(), a["body"]["neighbors"].clone()))
            .collect();
        let outgoing: Vec<_> = self
            .contacts
            .iter()
            .filter(|(_, c)| c.get("host").is_some() || c.get("outbox").is_some())
            .map(|(p, _)| p)
            .collect();
        let result = crypto(
            json!({"Routing":{"network":self.network,"node":self.id,"destination":destination,
            "excluded":excluded,"first_hop":first,"outgoing":outgoing,"graph":graph,"limits":{"nodes":64,"contacts":16}}}),
        )?;
        Ok(!result["path"].is_null())
    }

    pub(crate) fn prepare(&mut self, peer: &str) -> Result<Value> {
        let contact = self
            .contacts
            .get(peer)
            .ok_or("unconfigured outgoing peer")?;
        require(
            contact.get("host").is_some() || contact.get("outbox").is_some(),
            "contact has no outgoing adapter",
        )?;
        let mut ids: Vec<_> = self.state.messages.keys().cloned().collect();
        if let Some(cursor) = self.state.transit_cursors.get(peer) {
            let offset = ids.partition_point(|i| i <= cursor);
            ids.rotate_left(offset);
        }
        let prior = self
            .state
            .first_carried
            .get(peer)
            .cloned()
            .unwrap_or_default();
        let mut first = self
            .state
            .arrivals
            .iter()
            .filter(|id| !prior.contains(id))
            .cloned()
            .collect::<Vec<_>>();
        // Within the same two first-carriage slots, prefer a packet whose exact
        // configured destination is this contact. A copy for another neighbor
        // must not postpone the direct copy merely because it arrived earlier.
        // Keep relative relay order and both independent historical slots.
        first.sort_by_key(|id| self.state.messages[id]["packet"]["body"]["destination"] != peer);
        let mut ordered = first.into_iter().map(|id| (true, id)).collect::<Vec<_>>();
        ordered.extend(ids.into_iter().map(|id| (false, id)));
        let mut transits = Vec::new();
        let mut last = None;
        let mut first_count = 0;
        let mut carried = prior;
        let mut selected = std::collections::BTreeSet::new();
        for (first, id) in ordered {
            if transits.len() == 4 {
                break;
            }
            if first && first_count == 2 || selected.contains(&id) {
                continue;
            }
            if self.state.receipts.contains_key(&id) {
                continue;
            }
            let t = self
                .state
                .messages
                .get(&id)
                .ok_or("retained packet vanished")?;
            let checked = transit(t, &self.network, Value::Null, Value::Null)?;
            let visited: Vec<String> =
                serde_json::from_value(checked["visited"].clone()).map_err(|e| e.to_string())?;
            let destination = t["packet"]["body"]["destination"]
                .as_str()
                .ok_or("packet destination")?;
            if visited.iter().any(|p| p == peer)
                || visited.len() > 16
                || destination == self.id
                || !self.route(
                    destination,
                    visited.iter().filter(|p| *p != &self.id).cloned().collect(),
                    peer,
                )?
            {
                continue;
            }
            let previous = t["hops"]
                .as_array()
                .ok_or("hop list")?
                .last()
                .map(digest)
                .transpose()?
                .unwrap_or(id.clone());
            let hop = self.sign("hop",json!({"format":MESH,"network":self.network,"node_id":self.id,"packet_id":id,"previous":previous,"to":peer}))?;
            let mut forwarded = t.clone();
            forwarded["hops"]
                .as_array_mut()
                .ok_or("hop list")?
                .push(hop);
            let mut proposed = transits.clone();
            proposed.push(forwarded.clone());
            if bytes(&json!(proposed))?.len() + 8192 > EXCHANGE_LIMIT {
                continue;
            }
            transits.push(forwarded);
            selected.insert(id.clone());
            if first {
                first_count += 1;
            } else {
                last = Some(id.clone());
            }
            if !carried.contains(&id) {
                carried.push(id);
            }
        }
        require(carried.len() <= 256, "first carriage primitive capacity")?;
        self.retained_image = None;
        self.state.first_carried.insert(peer.into(), carried);
        if let Some(last) = last {
            self.state.transit_cursors.insert(peer.into(), last);
        }
        let mut keys: Vec<_> = self
            .state
            .receipts
            .keys()
            .chain(self.state.archives.keys())
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        if let Some(cursor) = self.state.receipt_cursors.get(peer) {
            let offset = keys.partition_point(|i| i <= cursor);
            keys.rotate_left(offset);
        }
        keys.truncate(16);
        // Selection grants no authority. Open and authenticate every selected
        // complete archive now; cold Node-open still reviews the full inventory.
        let mut selected = Vec::new();
        for id in &keys {
            let receipt = if let Some(object) = self.state.archives.get(id) {
                self.archive(id, object)?["receipt"].clone()
            } else {
                let receipt = self
                    .state
                    .receipts
                    .get(id)
                    .ok_or("selected receipt disappeared")?;
                schema(receipt, &self.network, "receipt")?;
                receipt.clone()
            };
            selected.push(receipt);
        }
        if let Some(last) = keys.last() {
            self.state.receipt_cursors.insert(peer.into(), last.clone());
        }
        let mut inventory: Vec<_> = self.state.messages.keys().cloned().collect();
        inventory.truncate(256);
        let inventory = self.sign(
            "inventory",
            json!({"format":MESH,"network":self.network,"node_id":self.id,"packet_ids":inventory}),
        )?;
        let body = json!({"format":MESH,"network":self.network,"node_id":self.id,"to":peer,
            "adverts":self.state.adverts.values().collect::<Vec<_>>(),"transits":transits,"receipts":selected,"inventory":inventory});
        let bundle = self.sign("exchange", body)?;
        exchange(&bundle, &self.network, &self.id, peer)?;
        require(
            bytes(&bundle)?.len() <= EXCHANGE_LIMIT,
            "complete exchange byte bound",
        )?;
        self.state.cursor = self
            .state
            .cursor
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("contact cursor exhausted")?;
        // Durable scheduling precedes opening a socket or publishing to a spool.
        self.save()?;
        Ok(bundle)
    }

    pub(crate) fn receive(&mut self, bundle: &Value, peer: &str) -> Result<Vec<String>> {
        let c = self
            .contacts
            .get(peer)
            .ok_or("unconfigured incoming peer")?;
        require(
            c.get("host").is_some() || c.get("inbox").is_some(),
            "contact has no incoming adapter",
        )?;
        let verified = exchange(bundle, &self.network, peer, &self.id)?;
        let body = &verified["body"];
        let old = self.state.clone();
        let retained_image = self.retained_image.take();
        let result = (|| {
            for advert in body["adverts"].as_array().ok_or("advert list")? {
                let checked = schema(advert, &self.network, "advert")?;
                let id = checked["body"]["node_id"]
                    .as_str()
                    .ok_or("advert identity")?
                    .to_owned();
                if id == self.id {
                    continue;
                }
                let accept = match self.state.adverts.get(&id) {
                    Some(existing) => {
                        checked["body"]["sequence"].as_u64() > existing["body"]["sequence"].as_u64()
                    }
                    None => {
                        require(self.state.adverts.len() < 64, "advert capacity")?;
                        true
                    }
                };
                if accept {
                    self.state.adverts.insert(id, advert.clone());
                }
            }
            let mut accepted = Vec::new();
            for t in body["transits"].as_array().ok_or("transit list")? {
                // Every envelope authenticates before body deduplication.
                transit(t, &self.network, json!(self.id), json!(peer))?;
                let id = digest(&t["packet"])?;
                if let Some(object) = self.state.archives.get(&id) {
                    let mut archive = self.archive(&id, object)?;
                    let object = if archive["transit"].is_null() {
                        // An asymmetric carrier may receive and archive a
                        // destination's authenticated receipt before its packet.
                        // Bind the independently checked complete transit to that
                        // exact receipt, then retain a new immutable object.
                        receipt_matches(
                            &archive["receipt"],
                            &t["packet"]["body"],
                            &t["routing"]["body"],
                        )?;
                        archive["transit"] = t.clone();
                        let raw = bytes(&archive)?;
                        let next = hex::encode(Sha256::digest(&raw));
                        let path = self.root.join("archive").join(format!("{next}.json"));
                        if path.exists() {
                            require(
                                read(&path, STATE_LIMIT)? == archive,
                                "existing complete custody archive differs",
                            )?;
                        } else {
                            let (count, size) = self.archive_inventory()?;
                            require(
                                count + 2 <= MAX_ARCHIVE_FILES
                                    && size + 2 * raw.len() as u64 <= MAX_ARCHIVE_BYTES,
                                "archive capacity including publication residue",
                            )?;
                            crate::contact_storage::execute(
                                &bytes(&json!({"ArchiveWrite":{
                                "path":path,"size_bytes":raw.len(),"sha256":next}}))?,
                                &raw,
                            )?;
                        }
                        next
                    } else {
                        require(
                            archive["transit"]["packet"] == t["packet"]
                                && archive["transit"]["routing"] == t["routing"],
                            "archived packet changed",
                        )?;
                        object.clone()
                    };
                    crate::contact_storage::execute(
                        &bytes(
                            &json!({"SyncMany":{"paths":[self.root.join("archive").join(format!("{object}.json"))]}}),
                        )?,
                        &[],
                    )?;
                    // Only after durable complete custody may the index advance.
                    // The old receipt-only object and every orphan stay retained.
                    self.state.archives.insert(id.clone(), object);
                } else if let Some(existing) = self.state.messages.get(&id) {
                    require(
                        existing["packet"] == t["packet"] && existing["routing"] == t["routing"],
                        "retained packet changed",
                    )?;
                } else {
                    require(self.state.messages.len() < 256, "active packet capacity")?;
                    self.state.messages.insert(id.clone(), t.clone());
                    self.state.arrivals.push(id.clone());
                }
                if t["packet"]["body"]["destination"] == self.id
                    && !self.state.receipts.contains_key(&id)
                    && !self.state.archives.contains_key(&id)
                {
                    require(self.state.receipts.len() < 256, "active receipt capacity")?;
                    let receipt = self.sign("receipt",json!({"format":MESH,"network":self.network,"node_id":self.id,
                        "packet_id":id,"frame_id":t["routing"]["body"]["frame_id"],"routing":t["routing"],
                        "outcome":"EVIDENCE_STORED_NOT_LEDGER_ACCEPTED"}))?;
                    schema(&receipt, &self.network, "receipt")?;
                    self.state.receipts.insert(id.clone(), receipt);
                }
                accepted.push(id);
            }
            for receipt in body["receipts"].as_array().ok_or("receipt list")? {
                let checked = schema(receipt, &self.network, "receipt")?;
                let id = checked["body"]["packet_id"]
                    .as_str()
                    .ok_or("receipt identity")?
                    .to_owned();
                if let Some(t) = self.state.messages.get(&id) {
                    receipt_matches(receipt, &t["packet"]["body"], &t["routing"]["body"])?;
                }
                if let Some(object) = self.state.archives.get(&id) {
                    require(
                        self.archive(&id, object)?["receipt"] == *receipt,
                        "archived receipt changed",
                    )?;
                } else {
                    require(
                        self.state.receipts.contains_key(&id) || self.state.receipts.len() < 256,
                        "receipt capacity",
                    )?;
                    if let Some(old) = self.state.receipts.get(&id) {
                        require(old == receipt, "retained receipt changed")?;
                    }
                    self.state.receipts.insert(id, receipt.clone());
                }
            }
            self.state
                .peer_inventory
                .insert(peer.into(), body["inventory"].clone());
            if self.state.exact(&old) {
                if let Some(raw) = &retained_image {
                    #[cfg(test)]
                    let started = super::service::monotonic()?;
                    crate::contact_storage::repeat_exact(
                        &self.root.join("native-mesh-state.json"),
                        raw,
                    )?;
                    #[cfg(test)]
                    super::service::trace_subwork("mesh-state-repeat-sync", started)?;
                    self.retained_image = retained_image;
                } else {
                    self.save()?;
                }
            } else {
                self.save()?;
            }
            Ok(accepted)
        })();
        if result.is_err() {
            self.state = old;
        }
        result
    }

    pub(crate) fn archive_completed(&mut self) -> Result<()> {
        if self.state.messages.len().max(self.state.receipts.len()) < 32 {
            return Ok(());
        }
        let (mut count, mut total) = self.archive_inventory()?;
        let ids: Vec<_> = self.state.receipts.keys().take(16).cloned().collect();
        if ids.is_empty() {
            if let Some(raw) = self.retained_image.take() {
                // No receipt means no archive or scheduling mutation. Retain
                // custody only after checking and synchronizing the exact image
                // authenticated or durably published during this lock lease.
                #[cfg(test)]
                let started = super::service::monotonic()?;
                crate::contact_storage::repeat_exact(
                    &self.root.join("native-mesh-state.json"),
                    &raw,
                )?;
                #[cfg(test)]
                super::service::trace_subwork("mesh-state-repeat-sync", started)?;
                self.retained_image = Some(raw);
                return Ok(());
            }
        }
        for id in ids {
            let receipt = self.state.receipts.get(&id).ok_or("receipt disappeared")?;
            let t = self.state.messages.get(&id);
            if let Some(t) = t {
                transit(t, &self.network, Value::Null, Value::Null)?;
                receipt_matches(receipt, &t["packet"]["body"], &t["routing"]["body"])?;
            }
            let value = json!({"format":FORMAT,"network":self.network,"node_id":self.id,"packet_id":id,"receipt":receipt,"transit":t});
            let raw = bytes(&value)?;
            let object = hex::encode(Sha256::digest(&raw));
            let path = self.root.join("archive").join(format!("{object}.json"));
            if !path.exists() {
                require(
                    count + 2 <= MAX_ARCHIVE_FILES
                        && total + 2 * raw.len() as u64 <= MAX_ARCHIVE_BYTES,
                    "archive capacity including publication residue",
                )?;
                crate::contact_storage::execute(
                    &bytes(
                        &json!({"ArchiveWrite":{"path":path,"size_bytes":raw.len(),"sha256":object}}),
                    )?,
                    &raw,
                )?;
                count += 1;
                total += raw.len() as u64;
            } else {
                require(
                    read(&path, STATE_LIMIT)? == value,
                    "existing custody archive differs",
                )?;
            }
            crate::contact_storage::execute(&bytes(&json!({"SyncMany":{"paths":[path]}}))?, &[])?;
            self.retained_image = None;
            self.state.archives.insert(id.clone(), object);
            self.state.messages.remove(&id);
            self.state.receipts.remove(&id);
            self.state.arrivals.retain(|i| i != &id);
            for ids in self.state.first_carried.values_mut() {
                ids.retain(|i| i != &id);
            }
        }
        self.save()
    }

    pub fn observation(&self) -> Value {
        json!({"format":FORMAT,"network":self.network,"node_id":self.id,"region":self.region,
            "known_nodes":self.state.adverts.len(),"retained_messages":self.state.messages.len(),
            "retained_receipts":self.state.receipts.len(),"archive_entries":self.state.archives.len(),
            "ledger_authority":false,"fixture_only":true})
    }

    pub(crate) fn advertised_destinations(&self) -> Result<Vec<(String, String)>> {
        self.state
            .adverts
            .iter()
            .map(|(id, advert)| {
                schema(advert, &self.network, "advert")?;
                Ok((
                    id.clone(),
                    advert["body"]["region"]
                        .as_str()
                        .ok_or("advert region")?
                        .to_owned(),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{contact::Frame, Hash};
    struct Fixture {
        root: PathBuf,
        configs: Vec<Value>,
        ids: Vec<String>,
        retain: bool,
    }
    impl Fixture {
        fn new(count: usize) -> Self {
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("rld-rust-contact-test-{}", random().unwrap()));
            let root = directory(&root).unwrap();
            let network = "11".repeat(32);
            let mut ids = Vec::new();
            for n in 0..count {
                let node_root = root.join(n.to_string());
                let identity = initialize(
                    &node_root,
                    &network,
                    &format!("{:02x}", n + 2).repeat(32),
                    "public-no-value-test",
                )
                .unwrap();
                ids.push(identity["node_id"].as_str().unwrap().into());
            }
            let configs=(0..count).map(|n| {
                let contacts=(0..count).filter(|p|(*p as isize-n as isize).abs()==1).map(|p|
                    json!({"peer":ids[p],"inbox":root.join(format!("spool-{p}-{n}")),"outbox":root.join(format!("spool-{n}-{p}"))})).collect::<Vec<_>>();
                json!({"format":MESH,"network":network,"state":root.join(n.to_string()),"contacts":contacts})
            }).collect();
            Self {
                root,
                configs,
                ids,
                retain: false,
            }
        }
        fn frame(&self) -> Vec<u8> {
            let payload=bytes(&json!({"format":crate::bft_network::FORMAT,"currency":"11".repeat(32),"region":"22".repeat(32),
                "evidence":{"snapshots":[]},"body":{"Submission":[]}})).unwrap();
            let hash = Hash(Sha256::digest(&payload).into());
            let mut frame = Frame {
                format: crate::contact::FRAME_FORMAT.into(),
                kind: "regional-bft".into(),
                source_chain_id: Hash::from_hex(&"22".repeat(32)).unwrap(),
                destination_chain_id: Hash::from_hex(&"22".repeat(32)).unwrap(),
                export_id: hash,
                payload_sha256: hash,
                payload_b64: STANDARD.encode(payload),
                message_id: Hash::ZERO,
            };
            frame.message_id = frame.message().unwrap();
            frame.retained_bytes().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.retain || std::thread::panicking() {
                eprintln!(
                    "Failed Rust mesh fixture retained at {}",
                    self.root.display()
                );
                return;
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn rust_multihop_custody_receipt_and_cold_restart_preserve_exact_frame() {
        let f = Fixture::new(3);
        for pair in [(1, 0), (2, 1), (1, 0)] {
            let bundle = Node::open(&f.configs[pair.0])
                .unwrap()
                .prepare(&f.ids[pair.1])
                .unwrap();
            Node::open(&f.configs[pair.1])
                .unwrap()
                .receive(&bundle, &f.ids[pair.0])
                .unwrap();
        }
        let raw = f.frame();
        let packet = Node::open(&f.configs[0])
            .unwrap()
            .enqueue(&raw, &f.ids[2])
            .unwrap();
        let ab = Node::open(&f.configs[0])
            .unwrap()
            .prepare(&f.ids[1])
            .unwrap();
        assert_eq!(ab["body"]["transits"].as_array().unwrap().len(), 1);
        Node::open(&f.configs[1])
            .unwrap()
            .receive(&ab, &f.ids[0])
            .unwrap();
        let bc = Node::open(&f.configs[1])
            .unwrap()
            .prepare(&f.ids[2])
            .unwrap();
        Node::open(&f.configs[2])
            .unwrap()
            .receive(&bc, &f.ids[1])
            .unwrap();
        let cold = Node::open(&f.configs[2]).unwrap();
        assert_eq!(cold.received_frames().unwrap(), vec![(packet.clone(), raw)]);
        assert_eq!(
            cold.state.receipts[&packet]["body"]["outcome"],
            "EVIDENCE_STORED_NOT_LEDGER_ACCEPTED"
        );
        drop(cold);
        let cb = Node::open(&f.configs[2])
            .unwrap()
            .prepare(&f.ids[1])
            .unwrap();
        Node::open(&f.configs[1])
            .unwrap()
            .receive(&cb, &f.ids[2])
            .unwrap();
        let ba = Node::open(&f.configs[1])
            .unwrap()
            .prepare(&f.ids[0])
            .unwrap();
        Node::open(&f.configs[0])
            .unwrap()
            .receive(&ba, &f.ids[1])
            .unwrap();
        assert!(Node::open(&f.configs[0])
            .unwrap()
            .state
            .receipts
            .contains_key(&packet));
    }

    #[test]
    #[ignore = "one fresh transport-only diagnostic; run exact with a 60-second outer deadline"]
    fn unchanged_pending_archive_reuses_exact_durable_image() {
        use std::os::unix::fs::MetadataExt;
        let started = std::time::Instant::now();
        let within_budget = || {
            assert!(
                started.elapsed().as_secs_f64() < 60.0,
                "pending archive diagnostic exhausted its original 60-second budget"
            );
        };
        let calls = |work: &[Value], phase: &str| -> u64 {
            work.iter()
                .filter(|row| row["phase"] == phase)
                .map(|row| row["calls"].as_u64().expect("typed aggregate call count"))
                .sum()
        };
        let mut f = Fixture::new(2);
        f.retain = true;
        eprintln!("Fresh pending archive diagnostic: {}", f.root.display());
        within_budget();
        let mut frames = Vec::new();
        for n in 0..32u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            frames.push(frame.retained_bytes().unwrap());
        }
        let mut node = Node::open(&f.configs[0]).unwrap();
        for batch in frames.chunks(4) {
            within_budget();
            node.enqueue_frame_batch(
                &batch.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &[f.ids[1].clone()],
            )
            .unwrap();
        }
        // Exercise durable scheduling metadata without delivery or a receipt.
        let priority = node
            .state
            .arrivals
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        node.prioritize_originated_packets(&priority).unwrap();
        node.prepare(&f.ids[1]).unwrap();
        assert_eq!(node.state.messages.len(), 32);
        assert!(node.state.receipts.is_empty());
        assert!(node.state.archives.is_empty());
        let state_before = node.state.clone();
        let canonical_before = bytes(&serde_json::to_value(&state_before).unwrap()).unwrap();
        let path = node.root.join("native-mesh-state.json");
        let image_before = fs::read(&path).unwrap();
        let inode_before = fs::metadata(&path).unwrap().ino();
        assert_eq!(node.retained_image.as_ref(), Some(&image_before));
        fs::write(
            f.root.join("pending-before-expanded.json"),
            &canonical_before,
        )
        .unwrap();
        fs::write(f.root.join("pending-before-image.json"), &image_before).unwrap();

        within_budget();
        super::super::service::start_work_trace();
        crate::contact_state_codec::start_encoding_trace();
        let archive_started = std::time::Instant::now();
        let archived = node.archive_completed();
        let archive_seconds = archive_started.elapsed().as_secs_f64();
        let encodings = crate::contact_state_codec::take_encoding_trace();
        let archive_work = super::super::service::take_work_trace();
        fs::write(
            f.root.join("pending-archive-operation.json"),
            bytes(&json!({
                "operation_ok":archived.is_ok(), "error":archived.as_ref().err(),
                "archive_seconds":archive_seconds, "encodings":encodings, "work":archive_work,
                "ledger_authority":false
            }))
            .unwrap(),
        )
        .unwrap();
        archived.unwrap();
        within_budget();
        let canonical_after = bytes(&serde_json::to_value(&node.state).unwrap()).unwrap();
        let image_after = fs::read(&path).unwrap();
        let inode_after = fs::metadata(&path).unwrap().ino();
        fs::write(f.root.join("pending-after-expanded.json"), &canonical_after).unwrap();
        fs::write(f.root.join("pending-after-image.json"), &image_after).unwrap();
        assert!(node.state.exact(&state_before));
        assert_eq!(canonical_before, canonical_after);
        assert_eq!(image_before, image_after);
        assert_eq!(node.retained_image.as_ref(), Some(&image_after));
        assert_eq!(node.archive_inventory().unwrap(), (0, 0));
        drop(node);

        // Clear only this serial diagnostic process's byte witnesses, then
        // authenticate all retained ground signatures through ordinary open.
        // This is not a new-process, independent or Native-ledger qualification.
        let cleared =
            crate::contact_witness::execute(&bytes(&json!("Clear")).unwrap(), &[]).unwrap();
        assert_eq!(cleared["entries"], 0);
        within_budget();
        super::super::service::start_work_trace();
        let cold_started = std::time::Instant::now();
        let cold = Node::open(&f.configs[0]).unwrap();
        let cold_seconds = cold_started.elapsed().as_secs_f64();
        let cold_work = super::super::service::take_work_trace();
        assert!(cold.state.exact(&state_before));
        assert_eq!(
            bytes(&serde_json::to_value(&cold.state).unwrap()).unwrap(),
            canonical_before
        );
        assert_eq!(fs::read(&path).unwrap(), image_before);
        assert_eq!(cold.retained_image.as_ref(), Some(&image_before));
        assert_eq!(calls(&cold_work, "transit-full-check"), 32);
        assert_eq!(calls(&cold_work, "transit-witness-hit"), 0);
        drop(cold);
        let elapsed = started.elapsed().as_secs_f64();
        let report = json!({
            "fixture_only":true, "ledger_authority":false,
            "pending_messages":32, "receipts":0, "archive_entries":0,
            "canonical_state_equal":true, "retained_image_equal":true,
            "state_inode_equal":inode_before==inode_after,
            "archive_seconds":archive_seconds, "encodings":encodings,
            "archive_work":archive_work, "cold_seconds":cold_seconds,
            "cold_work":cold_work, "elapsed_seconds":elapsed,
            "cold_scope":"same-process ordinary Node open after explicit witness clear",
            "scope_limit_seconds":60, "original_payment_delay_attribution":false
        });
        fs::write(
            f.root.join("pending-archive-counter.json"),
            bytes(&report).unwrap(),
        )
        .unwrap();
        eprintln!("Pending archive diagnostic: {report}");
        within_budget();
        // Run this assertion last: the old implementation must preserve all
        // evidence and complete the authentication check before the expected RED.
        assert_eq!(
            encodings.len(),
            0,
            "unchanged pending-only archive maintenance re-encoded the whole state"
        );
        assert_eq!(calls(&archive_work, "mesh-state-encode-transits"), 0);
        assert_eq!(calls(&archive_work, "mesh-state-save-complete"), 0);
        assert_eq!(
            calls(&archive_work, "mesh-state-repeat-sync"),
            1,
            "unchanged archive maintenance must repeat actual file and directory sync"
        );
        assert_eq!(inode_before, inode_after);
    }

    #[test]
    fn pending_archive_fallback_receipts_cold_and_changed_image_fail_closed() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(2);
        f.retain = true;
        eprintln!(
            "Fresh pending archive fallback/receipt/refusal guard: {}",
            f.root.display()
        );
        let mut frames = Vec::new();
        // The last sixteen frames are reserved for restoring the original
        // pending count after actual receipt migration, through normal enqueue.
        for n in 0..48u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut body: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            body["region"] = json!(region);
            let raw = bytes(&body).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            frames.push(frame.retained_bytes().unwrap());
        }
        let mut node = Node::open(&f.configs[0]).unwrap();
        for batch in frames[..32].chunks(4) {
            node.enqueue_frame_batch(
                &batch.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &[f.ids[1].clone()],
            )
            .unwrap();
        }
        let priority = node
            .state
            .arrivals
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        node.prioritize_originated_packets(&priority).unwrap();
        assert_eq!(node.state.messages.len(), 32);
        assert!(node.state.receipts.is_empty());
        let path = node.root.join("native-mesh-state.json");
        let before = fs::read(&path).unwrap();
        let expected = node.state.clone();
        assert_eq!(node.retained_image.as_ref(), Some(&before));
        crate::contact_state_codec::start_encoding_trace();
        super::super::service::start_work_trace();
        node.archive_completed().unwrap();
        let repeat_encodings = crate::contact_state_codec::take_encoding_trace();
        let repeat_work = super::super::service::take_work_trace();
        assert!(repeat_encodings.is_empty());
        assert_eq!(
            repeat_work
                .iter()
                .filter(|row| row["phase"] == "mesh-state-repeat-sync")
                .map(|row| row["calls"].as_u64().unwrap())
                .sum::<u64>(),
            1
        );
        assert!(!repeat_work
            .iter()
            .any(|row| row["phase"] == "mesh-state-save-complete"));
        assert!(node.state.exact(&expected));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(node.retained_image.as_ref(), Some(&before));
        assert_eq!(node.retained_image.take(), Some(before.clone()));
        crate::contact_state_codec::start_encoding_trace();
        super::super::service::start_work_trace();
        node.archive_completed().unwrap();
        let encoded = crate::contact_state_codec::take_encoding_trace();
        let fallback_work = super::super::service::take_work_trace();
        assert_eq!(
            encoded.len(),
            1,
            "absence of an exact image must perform the full save"
        );
        assert!(fallback_work
            .iter()
            .any(|row| row["phase"] == "mesh-state-save-complete" && row["calls"] == 1));
        assert!(!fallback_work
            .iter()
            .any(|row| row["phase"] == "mesh-state-repeat-sync"));
        assert!(node.state.exact(&expected));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(node.retained_image.as_ref(), Some(&before));

        // Real destination receipt signatures enter through ordinary receive.
        // The nonempty receipt branch must still migrate complete custody.
        let mut destination = Node::open(&f.configs[1]).unwrap();
        let exchange = node.prepare(&f.ids[1]).unwrap();
        destination.receive(&exchange, &f.ids[0]).unwrap();
        let reply = destination.prepare(&f.ids[0]).unwrap();
        node.receive(&reply, &f.ids[1]).unwrap();
        let completed = node.state.receipts.clone();
        assert!(!completed.is_empty() && completed.len() <= 16);
        let messages_before = node.state.messages.clone();
        let pending = messages_before
            .iter()
            .filter(|(id, _)| !completed.contains_key(*id))
            .map(|(id, transit)| (id.clone(), transit.clone()))
            .collect::<BTreeMap<_, _>>();
        let arrivals = node
            .state
            .arrivals
            .iter()
            .filter(|id| !completed.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        let mut first_carried = node.state.first_carried.clone();
        for ids in first_carried.values_mut() {
            ids.retain(|id| !completed.contains_key(id));
        }
        super::super::service::start_work_trace();
        node.archive_completed().unwrap();
        let receipt_work = super::super::service::take_work_trace();
        assert!(!receipt_work
            .iter()
            .any(|row| row["phase"] == "mesh-state-repeat-sync"));
        assert!(receipt_work
            .iter()
            .any(|row| row["phase"] == "mesh-state-save-complete" && row["calls"] == 1));
        assert_eq!(node.state.messages, pending);
        assert!(node.state.receipts.is_empty());
        assert_eq!(node.state.arrivals, arrivals);
        assert_eq!(node.state.first_carried, first_carried);
        assert_eq!(node.state.archives.len(), completed.len());
        for (id, receipt) in &completed {
            let archived = node.archive(id, &node.state.archives[id]).unwrap();
            assert_eq!(&archived["receipt"], receipt);
            assert_eq!(&archived["transit"], &messages_before[id]);
        }
        let expected = node.state.clone();
        let image = fs::read(&path).unwrap();
        drop(destination);
        drop(node);
        let cleared =
            crate::contact_witness::execute(&bytes(&json!("Clear")).unwrap(), &[]).unwrap();
        assert_eq!(cleared["entries"], 0);
        // Same-process ordinary cold authentication, not independent custody.
        let mut node = Node::open(&f.configs[0]).unwrap();
        assert!(node.state.exact(&expected));
        assert_eq!(fs::read(&path).unwrap(), image);
        assert_eq!(node.retained_image.as_ref(), Some(&image));

        // Restore exactly 32 pending packets using new signed packets. Otherwise
        // the unchanged below-watermark early return would bypass this refusal.
        for batch in frames[32..32 + completed.len()].chunks(4) {
            node.enqueue_frame_batch(
                &batch.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &[f.ids[1].clone()],
            )
            .unwrap();
        }
        assert_eq!(node.state.messages.len(), 32);
        assert!(node.state.receipts.is_empty());
        let expected = node.state.clone();
        let original = fs::read(&path).unwrap();
        assert_eq!(node.retained_image.as_ref(), Some(&original));
        let original_backup = f.root.join("original-image-before-fault.json");
        crate::keystore::private_create(&original_backup, &original).unwrap();
        assert_eq!(fs::read(&original_backup).unwrap(), original);
        let mut altered = original;
        *altered.last_mut().unwrap() ^= 1;
        fs::write(&path, &altered).unwrap();
        crate::contact_state_codec::start_encoding_trace();
        let error = node.archive_completed().unwrap_err();
        assert!(
            error.contains("retained contact state missing or changed"),
            "{error}"
        );
        assert!(crate::contact_state_codec::take_encoding_trace().is_empty());
        assert!(node.retained_image.is_none());
        assert!(node.state.exact(&expected));
        assert_eq!(
            fs::read(&path).unwrap(),
            altered,
            "failure silently repaired changed bytes"
        );
        assert!(started.elapsed().as_secs_f64() < 60.0);
        // Stop here: retain the changed image and the whole failed fixture.
    }

    #[test]
    fn pending_archive_empty_receipts_still_refuse_unsafe_inventory() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(2);
        f.retain = true;
        eprintln!(
            "Fresh pending archive inventory refusal guard: {}",
            f.root.display()
        );
        let mut frames = Vec::new();
        for n in 0..32u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut body: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            body["region"] = json!(region);
            let raw = bytes(&body).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            frames.push(frame.retained_bytes().unwrap());
        }
        let mut node = Node::open(&f.configs[0]).unwrap();
        for batch in frames.chunks(4) {
            node.enqueue_frame_batch(
                &batch.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &[f.ids[1].clone()],
            )
            .unwrap();
        }
        assert_eq!(node.state.messages.len(), 32);
        assert!(node.state.receipts.is_empty());
        let expected = node.state.clone();
        let path = node.root.join("native-mesh-state.json");
        let image = fs::read(&path).unwrap();
        assert_eq!(node.retained_image.as_ref(), Some(&image));
        let unsafe_entry = node.root.join("archive").join("retained-unsafe-directory");
        fs::create_dir(&unsafe_entry).unwrap();
        crate::contact_state_codec::start_encoding_trace();
        super::super::service::start_work_trace();
        let error = node.archive_completed().unwrap_err();
        let work = super::super::service::take_work_trace();
        assert!(error.contains("archive contains unsafe object"), "{error}");
        assert!(crate::contact_state_codec::take_encoding_trace().is_empty());
        assert!(!work
            .iter()
            .any(|row| row["phase"] == "mesh-state-repeat-sync"
                || row["phase"] == "mesh-state-save-complete"));
        assert!(node.state.exact(&expected));
        assert_eq!(fs::read(&path).unwrap(), image);
        assert!(unsafe_entry.is_dir());
        assert!(started.elapsed().as_secs_f64() < 60.0);
        // Stop here: no removal, repair or cold reopen of the refused fixture.
    }

    #[test]
    fn duplicate_authenticated_receive_preserves_exact_state_inode_and_cold_custody() {
        use std::os::unix::fs::MetadataExt;
        let mut f = Fixture::new(2);
        f.retain = true;
        let mut source = Node::open(&f.configs[0]).unwrap();
        let raw = f.frame();
        let packet = source.enqueue(&raw, &f.ids[1]).unwrap();
        let bundle = source.prepare(&f.ids[1]).unwrap();
        drop(source);
        let mut recipient = Node::open(&f.configs[1]).unwrap();
        recipient.receive(&bundle, &f.ids[0]).unwrap();
        let path = recipient.root.join("native-mesh-state.json");
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let messages = recipient.state.messages.clone();
        super::super::service::start_work_trace();
        let accepted = recipient.receive(&bundle, &f.ids[0]).unwrap();
        let duplicate_work = super::super::service::take_work_trace();
        let after_inode = fs::metadata(&path).unwrap().ino();
        assert_eq!(accepted, vec![packet.clone()]);
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(recipient.state.messages, messages);
        let mut altered = bundle["body"].clone();
        altered["transits"][0]["hops"][0]["signature"] = json!("00".repeat(64));
        let bad = Node::open(&f.configs[0])
            .unwrap()
            .sign("exchange", altered)
            .unwrap();
        assert!(recipient.receive(&bad, &f.ids[0]).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(recipient);
        let mut cold = Node::open(&f.configs[1]).unwrap();
        assert_eq!(cold.state.messages, messages);
        assert_eq!(cold.received_frames().unwrap(), vec![(packet.clone(), raw)]);
        super::super::service::start_work_trace();
        assert_eq!(cold.receive(&bundle, &f.ids[0]).unwrap(), vec![packet]);
        let cold_duplicate = super::super::service::take_work_trace();
        assert!(!cold_duplicate
            .iter()
            .any(|e| e["phase"] == "mesh-state-encode-transits"));
        assert!(cold_duplicate
            .iter()
            .any(|e| e["phase"] == "mesh-state-repeat-sync"));
        assert_eq!(fs::read(&path).unwrap(), before);
        eprintln!(
            "Exact duplicate receive: {}",
            json!({"state_inode_preserved":inode==after_inode,"complete_cold_custody":true,"ledger_authority":false})
        );
        assert_eq!(
            after_inode, inode,
            "fully authenticated unchanged receive rewrote the complete transport state"
        );
        let encodes = duplicate_work
            .iter()
            .filter(|e| e["phase"] == "mesh-state-encode-transits")
            .map(|e| e["calls"].as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(
            encodes, 0,
            "exact unchanged duplicate receive re-encoded its complete shared state"
        );
        assert_eq!(
            duplicate_work
                .iter()
                .find(|e| e["phase"] == "mesh-state-repeat-sync")
                .expect("unchanged duplicate must repeat actual durable publication")["calls"],
            1
        );
    }

    #[test]
    fn retained_image_comparison_preserves_every_metadata_field_and_number_bytes() {
        let f = Fixture::new(2);
        let node = Node::open(&f.configs[0]).unwrap();
        let original = node.state.clone();
        let value = serde_json::to_value(&original).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            let entry = &mut changed[field];
            *entry = match entry {
                Value::String(_) => json!("changed"),
                Value::Number(_) => json!(1),
                Value::Array(_) => json!(["changed"]),
                Value::Object(_) => match field.as_str() {
                    "archives" | "transit_cursors" | "receipt_cursors" => {
                        json!({"changed":"changed"})
                    }
                    _ => json!({"changed":[]}),
                },
                _ => panic!("unexpected typed state metadata"),
            };
            let changed: State = serde_json::from_value(changed).unwrap();
            assert!(!original.exact(&changed), "metadata field omitted: {field}");
        }
        let mut a = original.clone();
        let mut b = original;
        a.peer_inventory.insert(
            "number-test".into(),
            serde_json::from_str(r#"{"nested":[-0.0]}"#).unwrap(),
        );
        b.peer_inventory.insert(
            "number-test".into(),
            serde_json::from_str(r#"{"nested":[0.0]}"#).unwrap(),
        );
        assert!(a == b);
        assert!(!a.exact(&b));
        assert_ne!(
            bytes(&serde_json::to_value(a).unwrap()).unwrap(),
            bytes(&serde_json::to_value(b).unwrap()).unwrap()
        );
    }

    #[test]
    fn duplicate_receive_refuses_changed_or_missing_retained_image_without_repair() {
        for missing in [false, true] {
            let mut f = Fixture::new(2);
            f.retain = true;
            let mut source = Node::open(&f.configs[0]).unwrap();
            source.enqueue(&f.frame(), &f.ids[1]).unwrap();
            let bundle = source.prepare(&f.ids[1]).unwrap();
            drop(source);
            let mut recipient = Node::open(&f.configs[1]).unwrap();
            recipient.receive(&bundle, &f.ids[0]).unwrap();
            let state = serde_json::to_value(&recipient.state).unwrap();
            let path = recipient.root.join("native-mesh-state.json");
            let raw = fs::read(&path).unwrap();
            let backup = recipient.root.join("original-image-before-fault");
            if missing {
                fs::rename(&path, &backup).unwrap();
            } else {
                crate::keystore::private_create(&backup, &raw).unwrap();
                fs::write(&path, vec![b'x'; raw.len()]).unwrap();
            }
            assert!(recipient.receive(&bundle, &f.ids[0]).is_err());
            assert_eq!(serde_json::to_value(&recipient.state).unwrap(), state);
            assert!(recipient.retained_image.is_none());
            assert_eq!(fs::read(backup).unwrap(), raw);
            if missing {
                assert!(!path.exists());
            } else {
                assert_eq!(fs::read(path).unwrap(), vec![b'x'; raw.len()]);
            }
        }
    }

    #[test]
    fn altered_later_envelope_refuses_without_replacing_original_or_advancing_cursor() {
        let f = Fixture::new(2);
        let raw = f.frame();
        Node::open(&f.configs[0])
            .unwrap()
            .enqueue(&raw, &f.ids[1])
            .unwrap();
        let bundle = Node::open(&f.configs[0])
            .unwrap()
            .prepare(&f.ids[1])
            .unwrap();
        Node::open(&f.configs[1])
            .unwrap()
            .receive(&bundle, &f.ids[0])
            .unwrap();
        let before = read(&f.root.join("1/native-mesh-state.json"), STATE_LIMIT).unwrap();
        let mut altered = bundle["body"].clone();
        altered["transits"][0]["hops"][0]["signature"] = json!("00".repeat(64));
        let signed = Node::open(&f.configs[0])
            .unwrap()
            .sign("exchange", altered)
            .unwrap();
        assert!(Node::open(&f.configs[1])
            .unwrap()
            .receive(&signed, &f.ids[0])
            .is_err());
        assert_eq!(
            read(&f.root.join("1/native-mesh-state.json"), STATE_LIMIT).unwrap(),
            before
        );
        assert_eq!(
            Node::open(&f.configs[1])
                .unwrap()
                .received_frames()
                .unwrap()[0]
                .1,
            raw
        );
    }

    #[test]
    fn legacy_state_symlinks_and_duplicate_spools_refuse_without_rewrite() {
        let f = Fixture::new(2);
        let old = f.root.join("0/mesh-state.json");
        fs::write(&old, b"preserve legacy failure").unwrap();
        assert!(Node::open(&f.configs[0]).is_err());
        assert_eq!(fs::read(&old).unwrap(), b"preserve legacy failure");
        fs::remove_file(old).unwrap();
        let mut bad = f.configs[0].clone();
        bad["contacts"][0]["outbox"] = bad["contacts"][0]["inbox"].clone();
        assert!(Node::open(&bad).is_err());
        std::os::unix::fs::symlink(f.root.join("1"), f.root.join("unsafe")).unwrap();
        bad["state"] = json!(f.root.join("unsafe"));
        assert!(Node::open(&bad).is_err());
    }

    #[test]
    fn exclusive_runtime_lock_releases_and_corrupt_cold_state_refuses() {
        let f = Fixture::new(1);
        let node = Node::open(&f.configs[0]).unwrap();
        assert!(Node::open(&f.configs[0]).is_err());
        drop(node);
        Node::open(&f.configs[0]).unwrap();
        let path = f.root.join("0/native-mesh-state.json");
        let mut value = read(&path, STATE_LIMIT).unwrap();
        value["state"]["format"] = json!("wrong");
        atomic(&path, &value, STATE_LIMIT).unwrap();
        assert!(Node::open(&f.configs[0]).is_err());
    }

    #[test]
    fn receive_page_checks_each_foreign_archive_once_and_next_call_reads_again() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(3);
        f.retain = true;
        for (sender, receiver) in [(1, 0), (2, 1), (1, 0)] {
            let bundle = Node::open(&f.configs[sender])
                .unwrap()
                .prepare(&f.ids[receiver])
                .unwrap();
            Node::open(&f.configs[receiver])
                .unwrap()
                .receive(&bundle, &f.ids[sender])
                .unwrap();
        }
        let mut source = Node::open(&f.configs[0]).unwrap();
        let mut relay = Node::open(&f.configs[1]).unwrap();
        let mut destination = Node::open(&f.configs[2]).unwrap();
        for n in 0..48u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            source
                .enqueue(&frame.retained_bytes().unwrap(), &f.ids[2])
                .unwrap();
        }
        for _ in 0..24 {
            relay
                .receive(&source.prepare(&f.ids[1]).unwrap(), &f.ids[0])
                .unwrap();
            destination
                .receive(&relay.prepare(&f.ids[2]).unwrap(), &f.ids[1])
                .unwrap();
            relay
                .receive(&destination.prepare(&f.ids[1]).unwrap(), &f.ids[2])
                .unwrap();
        }
        assert_eq!(relay.state.receipts.len(), 48);
        relay.archive_completed().unwrap();
        relay.archive_completed().unwrap();
        assert_eq!(relay.state.archives.len(), 32);
        let raw = f.frame();
        let packet = source.enqueue(&raw, &f.ids[1]).unwrap();
        relay
            .receive(&source.prepare(&f.ids[1]).unwrap(), &f.ids[0])
            .unwrap();
        let state_path = relay.root.join("native-mesh-state.json");
        let original = fs::read(&state_path).unwrap();
        let messages = relay.state.messages.clone();
        let archives = relay.state.archives.clone();
        let seen = vec!["ff".repeat(32)];
        super::super::service::start_work_trace();
        let selected = relay.frame_page_selected(None, 4, &seen).unwrap();
        let trace = super::super::service::take_work_trace();
        let reads = trace
            .iter()
            .filter(|e| e["phase"] == "mesh-archive-read-bind")
            .map(|e| e["calls"].as_u64().unwrap_or(1))
            .sum::<u64>();
        assert_eq!(selected, vec![(packet.clone(), raw.clone())]);
        let (archive_id, object) = archives.iter().next().unwrap();
        let path = relay.root.join("archive").join(format!("{object}.json"));
        let bytes = fs::read(&path).unwrap();
        super::super::encoding_cost::start();
        let checked = relay.archive(archive_id, object).unwrap();
        let encodings = super::super::encoding_cost::take();
        assert_eq!(checked["packet_id"], *archive_id);
        let complete_encodes = encodings
            .get(&(bytes.len(), Sha256::digest(&bytes).into()))
            .copied()
            .unwrap_or(0);
        let missing = path.with_extension("retained-missing");
        fs::rename(&path, &missing).unwrap();
        assert!(
            relay.frame_page_selected(None, 4, &seen).is_err(),
            "later page reused stale archive authentication"
        );
        assert_eq!(fs::read(&state_path).unwrap(), original);
        fs::rename(&missing, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(source);
        drop(relay);
        let cold = Node::open(&f.configs[1]).unwrap();
        assert_eq!(cold.state.messages, messages);
        assert_eq!(cold.state.archives, archives);
        assert_eq!(
            cold.frame_page_selected(None, 4, &seen).unwrap(),
            vec![(packet, raw)]
        );
        assert_eq!(fs::read(&state_path).unwrap(), original);
        let expected = cold.state.clone();
        drop(cold);
        let clear = || {
            crate::contact_witness::execute(&super::super::bytes(&json!("Clear")).unwrap(), &[])
                .unwrap();
        };
        let mut serial_seconds = 0.0;
        let mut parallel_seconds = 0.0;
        // Empty process-local transit witnesses before every complete open.
        // Filesystem page caches are neither cleared nor claimed independent.
        for _ in 0..8 {
            clear();
            let at = std::time::Instant::now();
            let node = Node::open(&f.configs[1]).unwrap();
            assert!(node.state.exact(&expected));
            drop(node);
            serial_seconds += at.elapsed().as_secs_f64();
            clear();
            let at = std::time::Instant::now();
            let node = Node::open_parallel_fixture(&f.configs[1]).unwrap();
            assert!(node.state.exact(&expected));
            drop(node);
            parallel_seconds += at.elapsed().as_secs_f64();
        }
        assert_eq!(fs::read(&state_path).unwrap(), original);
        let (last_id, old_object) = archives.iter().next_back().unwrap();
        let old_path = f.root.join("1/archive").join(format!("{old_object}.json"));
        let mut bad = read(&old_path, STATE_LIMIT).unwrap();
        let mut body = bad["receipt"]["body"].clone();
        body["routing"]["signature"] = json!("00".repeat(64));
        bad["receipt"] = destination.sign("receipt", body).unwrap();
        let bad_raw = super::super::bytes(&bad).unwrap();
        let bad_object = hex::encode(Sha256::digest(&bad_raw));
        let bad_path = f.root.join("1/archive").join(format!("{bad_object}.json"));
        crate::keystore::private_create(&bad_path, &bad_raw).unwrap();
        let mut image = read(&state_path, STATE_LIMIT).unwrap();
        image["state"]["archives"][last_id] = json!(bad_object);
        crate::keystore::private_create(&state_path.with_extension("original-retained"), &original)
            .unwrap();
        atomic(&state_path, &image, STATE_LIMIT).unwrap();
        let failed_image = fs::read(&state_path).unwrap();
        clear();
        let serial_error = Node::open(&f.configs[1]).err().unwrap();
        clear();
        let parallel_error = Node::open_parallel_fixture(&f.configs[1]).err().unwrap();
        assert_eq!(serial_error, parallel_error);
        assert_eq!(serial_error, "contact signature invalid");
        assert_eq!(fs::read(&state_path).unwrap(), failed_image);
        assert_eq!(fs::read(&bad_path).unwrap(), bad_raw);
        assert!(old_path.exists(), "old complete archive was removed");
        assert!(!PARALLEL_COLD_FIXTURE.with(std::cell::Cell::get));
        drop(destination);
        eprintln!(
            "Foreign archive page: {}",
            json!({"archive_count":32,"actual_reads":reads,
            "seconds":started.elapsed().as_secs_f64(),"ledger_authority":false,
            "cold_opens_per_schedule":8,"serial_cold_seconds":serial_seconds,
            "two_worker_cold_seconds":parallel_seconds,"late_bad_nested_route_refused":true})
        );
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "foreign archive page budget"
        );
        assert_eq!(
            reads, 32,
            "one page repeated complete reads of already authenticated foreign archives"
        );
        assert_eq!(
            complete_encodes, 1,
            "archive digest re-encoded complete bytes already canonically checked during this read"
        );
    }

    #[test]
    fn receipt_page_authenticates_selected_archives_before_bounded_carriage() {
        let f = Fixture::new(2);
        for n in 0..48u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            Node::open(&f.configs[0])
                .unwrap()
                .enqueue(&frame.retained_bytes().unwrap(), &f.ids[1])
                .unwrap();
        }
        for _ in 0..24 {
            let bundle = Node::open(&f.configs[0])
                .unwrap()
                .prepare(&f.ids[1])
                .unwrap();
            Node::open(&f.configs[1])
                .unwrap()
                .receive(&bundle, &f.ids[0])
                .unwrap();
        }
        assert_eq!(Node::open(&f.configs[1]).unwrap().state.receipts.len(), 48);
        for _ in 0..3 {
            let bundle = Node::open(&f.configs[1])
                .unwrap()
                .prepare(&f.ids[0])
                .unwrap();
            Node::open(&f.configs[0])
                .unwrap()
                .receive(&bundle, &f.ids[1])
                .unwrap();
        }
        for _ in 0..2 {
            Node::open(&f.configs[0])
                .unwrap()
                .archive_completed()
                .unwrap();
        }
        let mut node = Node::open(&f.configs[0]).unwrap();
        assert_eq!(node.state.archives.len(), 32);
        super::super::service::start_work_trace();
        let bundle = node.prepare(&f.ids[1]).unwrap();
        let trace = super::super::service::take_work_trace();
        let checked = trace
            .iter()
            .filter(|e| e["phase"] == "receipt-schema")
            .map(|e| e["calls"].as_u64().unwrap_or(1))
            .sum::<u64>();
        assert_eq!(bundle["body"]["receipts"].as_array().unwrap().len(), 16);
        for receipt in bundle["body"]["receipts"].as_array().unwrap() {
            schema(receipt, &node.network, "receipt").unwrap();
        }
        assert!(
            checked <= 16,
            "one bounded page revalidated {checked} historical archive receipts"
        );
        let cursor = node.state.receipt_cursors[&f.ids[1]].clone();
        let (id, object) = node
            .state
            .archives
            .iter()
            .find(|(id, _)| *id > &cursor)
            .unwrap();
        let id = id.clone();
        let object = object.clone();
        let path = node.root.join("archive").join(format!("{object}.json"));
        let original = fs::read(&path).unwrap();
        let state_before = fs::read(node.root.join("native-mesh-state.json")).unwrap();
        let missing = path.with_extension("retained-missing");
        fs::rename(&path, &missing).unwrap();
        assert!(
            node.prepare(&f.ids[1]).is_err(),
            "selected missing archive was cached as custody"
        );
        assert_eq!(
            fs::read(node.root.join("native-mesh-state.json")).unwrap(),
            state_before
        );
        fs::rename(&missing, &path).unwrap();
        let mut bad: Value = serde_json::from_slice(&original).unwrap();
        bad["receipt"]["signature"] = json!("00".repeat(64));
        let bad_object = digest(&bad).unwrap();
        let bad_path = node.root.join("archive").join(format!("{bad_object}.json"));
        crate::keystore::private_create(&bad_path, &bytes(&bad).unwrap()).unwrap();
        node.state.archives.insert(id, bad_object);
        assert!(
            node.prepare(&f.ids[1]).is_err(),
            "hash-consistent selected bad receipt signature was accepted"
        );
        assert_eq!(
            fs::read(node.root.join("native-mesh-state.json")).unwrap(),
            state_before
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        node.save().unwrap();
        let poisoned_state = fs::read(node.root.join("native-mesh-state.json")).unwrap();
        drop(node);
        assert!(
            Node::open(&f.configs[0]).is_err(),
            "cold open accepted hash-consistent bad archived receipt"
        );
        assert_eq!(
            fs::read(f.root.join("0/native-mesh-state.json")).unwrap(),
            poisoned_state
        );
        assert!(bad_path.exists(), "bad original evidence was removed");
    }

    #[test]
    fn four_frame_broadcast_retains_complete_destination_batch_with_one_image_publication() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(4);
        f.retain = true;
        for n in 0..4 {
            f.configs[n]["contacts"] = json!((0..4)
                .filter(|p| *p != n)
                .map(
                    |p| json!({"peer":f.ids[p],"inbox":f.root.join(format!("spool-{p}-{n}")),
                    "outbox":f.root.join(format!("spool-{n}-{p}"))})
                )
                .collect::<Vec<_>>());
        }
        eprintln!(
            "Fresh four-frame transport batch fixture: {}",
            f.root.display()
        );
        let mut frames = Vec::new();
        for n in 0..4u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            frames.push(frame.retained_bytes().unwrap());
        }
        let mut source = Node::open(&f.configs[0]).unwrap();
        super::super::service::start_work_trace();
        let raws = frames.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let packets = source.enqueue_frame_batch(&raws, &f.ids[1..]).unwrap();
        let trace = super::super::service::take_work_trace();
        let publications = trace
            .iter()
            .filter(|entry| entry["phase"] == "mesh-state-encode-finish")
            .map(|entry| entry["calls"].as_u64().unwrap_or(1))
            .sum::<u64>();
        assert_eq!(source.state.messages.len(), 12);
        let retained = source.state.messages.clone();
        let state_path = source.root.join("native-mesh-state.json");
        let original = fs::read(&state_path).unwrap();
        let mut bad = frames[3].clone();
        bad[0] ^= 1;
        assert!(source
            .enqueue_frame_batch(&[&f.frame(), &bad], &f.ids[1..])
            .is_err());
        assert!(source
            .enqueue_frame_batch(&[&frames[0], &frames[0]], &f.ids[1..])
            .is_err());
        assert!(source
            .enqueue_frame_batch(&[frames[0].as_slice(); 5], &f.ids[1..])
            .is_err());
        assert_eq!(source.state.messages, retained);
        assert_eq!(fs::read(&state_path).unwrap(), original);
        assert_eq!(
            source.enqueue_frame_batch(&raws, &f.ids[1..]).unwrap(),
            packets
        );
        assert_eq!(fs::read(&state_path).unwrap(), original);
        drop(source);
        let mut source = Node::open(&f.configs[0]).unwrap();
        assert_eq!(source.state.messages, retained);
        assert_eq!(fs::read(&state_path).unwrap(), original);
        for destination in 1..4 {
            let mut recipient = Node::open(&f.configs[destination]).unwrap();
            for _ in 0..4 {
                let bundle = source.prepare(&f.ids[destination]).unwrap();
                recipient.receive(&bundle, &f.ids[0]).unwrap();
            }
            let received = recipient.state.messages.clone();
            for (frame, ids) in frames.iter().zip(&packets) {
                let packet = &ids[destination - 1];
                assert_eq!(
                    STANDARD
                        .decode(
                            received[packet]["packet"]["body"]["frame"]
                                .as_str()
                                .unwrap()
                        )
                        .unwrap(),
                    *frame
                );
                assert_eq!(
                    recipient.state.receipts[packet]["body"]["outcome"],
                    "EVIDENCE_STORED_NOT_LEDGER_ACCEPTED"
                );
            }
            drop(recipient);
            assert_eq!(
                Node::open(&f.configs[destination]).unwrap().state.messages,
                received
            );
        }
        eprintln!(
            "Four-frame transport batch: {}",
            json!({"publications":publications,"frames":4,"destinations":3,
            "packets":12,"seconds":started.elapsed().as_secs_f64(),"ledger_authority":false})
        );
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "four-frame transport batch budget"
        );
        assert_eq!(
            publications, 1,
            "one ordinary broadcast repeatedly published the complete transport image"
        );
    }

    #[test]
    fn complete_frame_batch_capacity_refuses_before_partial_publication() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(4);
        f.retain = true;
        let mut frames = Vec::new();
        for n in 0..88u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            frames.push(frame.retained_bytes().unwrap());
        }
        eprintln!("Fresh frame-batch capacity fixture: {}", f.root.display());
        let mut node = Node::open(&f.configs[0]).unwrap();
        for batch in frames[..84].chunks(4) {
            node.enqueue_frame_batch(
                &batch.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                &f.ids[1..],
            )
            .unwrap();
        }
        assert_eq!(node.state.messages.len(), 252);
        let before = fs::read(node.root.join("native-mesh-state.json")).unwrap();
        let retained = node.state.messages.clone();
        let error = node
            .enqueue_frame_batch(&[&frames[0], &frames[84], &frames[85]], &f.ids[1..])
            .unwrap_err();
        assert_eq!(error, "active packet capacity reached; retain old evidence");
        assert_eq!(node.state.messages, retained);
        assert_eq!(
            fs::read(node.root.join("native-mesh-state.json")).unwrap(),
            before
        );
        drop(node);
        let cold = Node::open(&f.configs[0]).unwrap();
        assert_eq!(cold.state.messages, retained);
        assert_eq!(
            fs::read(cold.root.join("native-mesh-state.json")).unwrap(),
            before
        );
        assert!(
            started.elapsed().as_secs_f64() < 60.0,
            "complete frame-batch capacity budget"
        );
    }

    #[test]
    fn configured_destination_copy_uses_first_carriage_before_alternate_relay_copies() {
        let mut f = Fixture::new(4);
        f.retain = true;
        for n in 0..4 {
            f.configs[n]["contacts"] = json!((0..4)
                .filter(|p| *p != n)
                .map(
                    |p| json!({"peer":f.ids[p],"inbox":f.root.join(format!("spool-{p}-{n}")),
                    "outbox":f.root.join(format!("spool-{n}-{p}"))})
                )
                .collect::<Vec<_>>());
        }
        eprintln!(
            "Fresh direct-destination carriage fixture: {}",
            f.root.display()
        );
        let mut source = Node::open(&f.configs[0]).unwrap();
        for n in 1..4 {
            let bundle = Node::open(&f.configs[n])
                .unwrap()
                .prepare(&f.ids[0])
                .unwrap();
            source.receive(&bundle, &f.ids[n]).unwrap();
        }
        let packets = source
            .enqueue_destinations(&f.frame(), &f.ids[1..])
            .unwrap();
        source.prioritize_originated_packets(&packets).unwrap();
        let bundle = source.prepare(&f.ids[3]).unwrap();
        let transits = bundle["body"]["transits"].as_array().unwrap();
        assert!(transits.len() <= 4);
        assert!(
            transits
                .iter()
                .take(2)
                .any(|transit| transit["routing"]["body"]["packet_id"] == packets[2]),
            "direct configured destination lost its first-carriage slot to alternate relay copies"
        );
        let preserved = source.state.messages.clone();
        drop(source);
        let mut recipient = Node::open(&f.configs[3]).unwrap();
        recipient.receive(&bundle, &f.ids[0]).unwrap();
        assert!(recipient
            .received_frames()
            .unwrap()
            .iter()
            .any(|(id, raw)| id == &packets[2] && raw == &f.frame()));
        drop(recipient);
        let cold = Node::open(&f.configs[0]).unwrap();
        assert_eq!(cold.state.messages, preserved);
    }

    #[test]
    fn durable_save_encodes_its_exact_complete_image_once() {
        let started = std::time::Instant::now();
        let mut f = Fixture::new(2);
        f.retain = true;
        let mut node = Node::open(&f.configs[0]).unwrap();
        node.enqueue(&f.frame(), &f.ids[1]).unwrap();
        let path = node.root.join("native-mesh-state.json");
        let before = fs::read(&path).unwrap();
        crate::contact_state_codec::start_encoding_trace();
        node.save().unwrap();
        let encodings = crate::contact_state_codec::take_encoding_trace();
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after);
        assert_eq!(node.retained_image.as_ref(), Some(&after));
        for entry in &encodings {
            assert_eq!(entry["size_bytes"], after.len());
            assert_eq!(entry["sha256"], hex::encode(Sha256::digest(&after)));
        }
        drop(node);
        let mut cold = Node::open(&f.configs[0]).unwrap();
        assert_eq!(cold.retained_image.as_ref(), Some(&after));
        println!(
            "complete-state-encodings {}",
            json!({"encodings":encodings,
            "elapsed_seconds":started.elapsed().as_secs_f64(),"fixture":f.root})
        );
        assert!(started.elapsed().as_secs_f64() < 30.0);
        assert_eq!(
            encodings.len(),
            1,
            "same durable image encoded more than once"
        );
        let preserved = path.with_file_name("state-before-write-refusal.json");
        assert!(!preserved.exists());
        fs::rename(&path, &preserved).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(
            cold.save().is_err(),
            "non-file target accepted a state image"
        );
        assert!(cold.retained_image.is_none());
        assert_eq!(fs::read(preserved).unwrap(), after);
        assert!(path.is_dir());
        assert!(started.elapsed().as_secs_f64() < 30.0);
    }

    #[test]
    fn directory_neighbor_turn_opens_one_authenticated_transport_image() {
        let mut f = Fixture::new(4);
        for n in 0..4 {
            let peers = if n == 0 {
                vec![1usize, 2, 3]
            } else {
                vec![0usize]
            };
            f.configs[n]["contacts"] = json!(peers.into_iter().map(|p|json!({"peer":f.ids[p],
                "inbox":f.root.join(format!("spool-{p}-{n}")),"outbox":f.root.join(format!("spool-{n}-{p}"))})).collect::<Vec<_>>());
        }
        let raw = f.frame();
        {
            let mut node = Node::open(&f.configs[0]).unwrap();
            node.enqueue_destinations(&raw, &f.ids[1..]).unwrap();
        }
        super::super::service::start_work_trace();
        assert!(super::super::service::spool_directory_turn(&f.configs[0])
            .unwrap()
            .is_empty());
        let trace = super::super::service::take_work_trace();
        let save = trace
            .iter()
            .find(|e| e["phase"] == "mesh-state-save-complete")
            .expect("complete durable-save observation");
        let mut phases = 0.0;
        for phase in [
            "mesh-state-metadata",
            "mesh-state-codec-begin",
            "mesh-state-encode-transits",
            "mesh-state-encode-finish",
            "mesh-state-durable-write",
            "mesh-state-codec-cleanup",
        ] {
            let entry = trace.iter().find(|e| e["phase"] == phase).unwrap();
            assert_eq!(entry["calls"], save["calls"]);
            phases += entry["seconds"].as_f64().unwrap();
        }
        assert!(save["calls"].as_u64().unwrap() > 0);
        assert!(phases <= save["seconds"].as_f64().unwrap());
        let opens = trace
            .iter()
            .filter(|e| e["phase"] == "mesh-state-decode-expand")
            .map(|e| e["calls"].as_u64().unwrap_or(1))
            .sum::<u64>();
        assert_eq!(
            opens, 1,
            "one directory turn reopened the same authenticated transport image"
        );
        for n in 1..4 {
            assert!(super::super::service::spool_directory_turn(&f.configs[n])
                .unwrap()
                .is_empty());
            let node = Node::open(&f.configs[n]).unwrap();
            assert_eq!(node.received_frames().unwrap().len(), 1);
            assert_eq!(node.received_frames().unwrap()[0].1, raw);
            assert_eq!(node.state.receipts.len(), 1);
        }
        assert!(super::super::service::spool_directory_turn(&f.configs[0])
            .unwrap()
            .is_empty());
        let cold = Node::open(&f.configs[0]).unwrap();
        assert_eq!(cold.state.receipts.len(), 3);
        let contacts = cold.contacts.clone();
        let cursor = cold.state.cursor;
        drop(cold);
        let first = contacts.keys().next().unwrap();
        let contact = &contacts[first];
        let invalid = json!({"body":{},"format":"invalid-exchange"});
        let path = Path::new(contact["inbox"].as_str().unwrap())
            .join(format!("{}.json", digest(&invalid).unwrap()));
        crate::keystore::private_create(&path, &bytes(&invalid).unwrap()).unwrap();
        let outboxes = contacts
            .iter()
            .filter(|(id, _)| *id != first)
            .map(|(_, c)| PathBuf::from(c["outbox"].as_str().unwrap()))
            .collect::<Vec<_>>();
        let errors = super::super::service::spool_directory_turn(&f.configs[0]).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(path.exists(), "failed incoming evidence was deleted");
        for outbox in outboxes {
            assert!(
                fs::read_dir(outbox).unwrap().count() > 0,
                "later neighbor was suppressed after a refusal"
            );
        }
        assert_eq!(
            Node::open(&f.configs[0]).unwrap().state.cursor,
            cursor + 2,
            "later directory neighbors did not each prepare after durable-state reopen"
        );
    }

    #[test]
    fn complete_frame_destination_batch_preserves_cold_ids_and_rejects_bad_input() {
        let f = Fixture::new(3);
        let raw = f.frame();
        let destinations = f.ids[1..].to_vec();
        let mut node = Node::open(&f.configs[0]).unwrap();
        let packets = node.enqueue_destinations(&raw, &destinations).unwrap();
        assert_eq!(packets.len(), 2);
        assert_ne!(packets[0], packets[1]);
        for (destination, packet) in destinations.iter().zip(&packets) {
            assert_eq!(
                node.state.messages[packet]["packet"]["body"]["destination"],
                *destination
            );
            assert_eq!(
                STANDARD
                    .decode(
                        node.state.messages[packet]["packet"]["body"]["frame"]
                            .as_str()
                            .unwrap()
                    )
                    .unwrap(),
                raw
            );
        }
        let before = fs::read(node.root.join("native-mesh-state.json")).unwrap();
        assert!(node
            .enqueue_destinations(&raw, &[destinations[0].clone(), destinations[0].clone()])
            .is_err());
        let mut bad = raw.clone();
        bad[0] ^= 1;
        assert!(node.enqueue_destinations(&bad, &destinations).is_err());
        assert!(node
            .enqueue_destinations(&raw, &vec![destinations[0].clone(); 17])
            .is_err());
        assert_eq!(
            fs::read(node.root.join("native-mesh-state.json")).unwrap(),
            before
        );
        drop(node);
        let mut cold = Node::open(&f.configs[0]).unwrap();
        let reversed = destinations.iter().rev().cloned().collect::<Vec<_>>();
        assert_eq!(
            cold.enqueue_destinations(&raw, &reversed).unwrap(),
            packets.iter().rev().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            fs::read(cold.root.join("native-mesh-state.json")).unwrap(),
            before
        );
    }

    #[test]
    fn unseen_archived_destination_frame_keeps_native_receive_priority() {
        let f = Fixture::new(2);
        for n in 0..32u8 {
            let mut frame: Frame = serde_json::from_slice(&f.frame()).unwrap();
            let mut payload: Value =
                serde_json::from_slice(&STANDARD.decode(&frame.payload_b64).unwrap()).unwrap();
            let region = Hash::from_hex(&hex::encode([n + 32; 32])).unwrap();
            payload["region"] = json!(region);
            let raw = bytes(&payload).unwrap();
            frame.source_chain_id = region;
            frame.destination_chain_id = region;
            frame.payload_sha256 = Hash(Sha256::digest(&raw).into());
            frame.export_id = frame.payload_sha256;
            frame.payload_b64 = STANDARD.encode(raw);
            frame.message_id = frame.message().unwrap();
            Node::open(&f.configs[0])
                .unwrap()
                .enqueue(&frame.retained_bytes().unwrap(), &f.ids[1])
                .unwrap();
        }
        for _ in 0..16 {
            let exchange = Node::open(&f.configs[0])
                .unwrap()
                .prepare(&f.ids[1])
                .unwrap();
            Node::open(&f.configs[1])
                .unwrap()
                .receive(&exchange, &f.ids[0])
                .unwrap();
        }
        Node::open(&f.configs[1])
            .unwrap()
            .archive_completed()
            .unwrap();
        let node = Node::open(&f.configs[1]).unwrap();
        assert_eq!(node.state.archives.len(), 16);
        let pending = node.state.archives.keys().next().unwrap().clone();
        let seen = node
            .state
            .messages
            .keys()
            .chain(node.state.archives.keys())
            .filter(|id| **id != pending)
            .cloned()
            .collect::<Vec<_>>();
        let before = fs::read(node.root.join("native-mesh-state.json")).unwrap();
        let page = node.frame_page_selected(Some(&pending), 4, &seen).unwrap();
        assert!(
            page.iter().any(|(id, _)| *id == pending),
            "unseen archived destination frame lost first-processing priority"
        );
        assert_eq!(
            fs::read(node.root.join("native-mesh-state.json")).unwrap(),
            before
        );
        assert_eq!(page.len(), 4);
        let active = node.state.messages.keys().next().unwrap().clone();
        let mixed_seen = seen
            .iter()
            .filter(|id| **id != active)
            .cloned()
            .collect::<Vec<_>>();
        let mixed = node
            .frame_page_selected(Some(&pending), 4, &mixed_seen)
            .unwrap();
        assert!(mixed.iter().any(|(id, _)| *id == pending));
        assert!(mixed.iter().any(|(id, _)| *id == active));
        assert_eq!(
            mixed
                .iter()
                .filter(|(id, _)| mixed_seen.contains(id))
                .count(),
            2
        );
        drop(node);
        let cold = Node::open(&f.configs[1]).unwrap();
        assert_eq!(
            cold.frame_page_selected(Some(&pending), 4, &mixed_seen)
                .unwrap(),
            mixed
        );
    }

    #[test]
    fn receipt_only_archive_retains_later_authenticated_packet_without_rewriting_old_bytes() {
        let mut f = Fixture::new(3);
        for n in 0..3 {
            f.configs[n]["contacts"] = json!((0..3).filter(|p|*p!=n).map(|p|json!({"peer":f.ids[p],
                "inbox":f.root.join(format!("spool-{p}-{n}")),"outbox":f.root.join(format!("spool-{n}-{p}"))})).collect::<Vec<_>>());
        }
        let adverts = Node::open(&f.configs[2])
            .unwrap()
            .prepare(&f.ids[0])
            .unwrap();
        Node::open(&f.configs[0])
            .unwrap()
            .receive(&adverts, &f.ids[2])
            .unwrap();
        for n in 0..32u8 {
            let region = hex::encode([n + 32; 32]);
            let payload = bytes(&json!({"format":crate::bft_network::FORMAT,"currency":"11".repeat(32),"region":region,
                "evidence":{"snapshots":[]},"body":{"Submission":[]}})).unwrap();
            let hash = Hash(Sha256::digest(&payload).into());
            let mut frame = Frame {
                format: crate::contact::FRAME_FORMAT.into(),
                kind: "regional-bft".into(),
                source_chain_id: Hash::from_hex(&region).unwrap(),
                destination_chain_id: Hash::from_hex(&region).unwrap(),
                export_id: hash,
                payload_sha256: hash,
                payload_b64: STANDARD.encode(payload),
                message_id: Hash::ZERO,
            };
            frame.message_id = frame.message().unwrap();
            Node::open(&f.configs[0])
                .unwrap()
                .enqueue(&frame.retained_bytes().unwrap(), &f.ids[1])
                .unwrap();
        }
        // Prepare legitimate alternate-path packets before the destination's
        // receipts reach their future carrier. This is transport only.
        let mut late = Vec::new();
        for _ in 0..16 {
            late.push(
                Node::open(&f.configs[0])
                    .unwrap()
                    .prepare(&f.ids[2])
                    .unwrap(),
            );
            let direct = Node::open(&f.configs[0])
                .unwrap()
                .prepare(&f.ids[1])
                .unwrap();
            Node::open(&f.configs[1])
                .unwrap()
                .receive(&direct, &f.ids[0])
                .unwrap();
        }
        assert_eq!(Node::open(&f.configs[1]).unwrap().state.receipts.len(), 32);
        for _ in 0..2 {
            let receipts = Node::open(&f.configs[1])
                .unwrap()
                .prepare(&f.ids[2])
                .unwrap();
            assert!(receipts["body"]["transits"].as_array().unwrap().is_empty());
            Node::open(&f.configs[2])
                .unwrap()
                .receive(&receipts, &f.ids[1])
                .unwrap();
        }
        Node::open(&f.configs[2])
            .unwrap()
            .archive_completed()
            .unwrap();
        let node = Node::open(&f.configs[2]).unwrap();
        assert_eq!(node.state.messages.len(), 0);
        let (packet, original) = node.state.archives.iter().next().unwrap();
        let packet = packet.clone();
        let original = original.clone();
        assert!(node.archive(&packet, &original).unwrap()["transit"].is_null());
        let path = node.root.join("archive").join(format!("{original}.json"));
        let original_bytes = fs::read(&path).unwrap();
        drop(node);
        let mut body = late
            .iter()
            .find(|bundle| {
                bundle["body"]["transits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| digest(&t["packet"]).unwrap() == packet)
            })
            .unwrap()["body"]
            .clone();
        let transit = body["transits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| digest(&t["packet"]).unwrap() == packet)
            .unwrap()
            .clone();
        body["transits"] = json!([transit.clone()]);
        let exchange = Node::open(&f.configs[0])
            .unwrap()
            .sign("exchange", body)
            .unwrap();
        Node::open(&f.configs[2])
            .unwrap()
            .receive(&exchange, &f.ids[0])
            .unwrap();
        let node = Node::open(&f.configs[2]).unwrap();
        let replacement = node.state.archives[&packet].clone();
        assert_ne!(replacement, original);
        let complete = node.archive(&packet, &replacement).unwrap();
        assert_eq!(complete["transit"], transit);
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        assert!(node.state.messages.is_empty());
        drop(node);
        Node::open(&f.configs[2])
            .unwrap()
            .receive(&exchange, &f.ids[0])
            .unwrap();
        assert_eq!(
            Node::open(&f.configs[2]).unwrap().state.archives[&packet],
            replacement
        );
        let before = fs::read(f.root.join("2/native-mesh-state.json")).unwrap();
        let mut corrupt = exchange["body"].clone();
        corrupt["transits"][0]["hops"][0]["signature"] = json!("00".repeat(64));
        let corrupt = Node::open(&f.configs[0])
            .unwrap()
            .sign("exchange", corrupt)
            .unwrap();
        assert!(Node::open(&f.configs[2])
            .unwrap()
            .receive(&corrupt, &f.ids[0])
            .is_err());
        assert_eq!(
            fs::read(f.root.join("2/native-mesh-state.json")).unwrap(),
            before
        );
        assert_eq!(fs::read(path).unwrap(), original_bytes);
    }
}
