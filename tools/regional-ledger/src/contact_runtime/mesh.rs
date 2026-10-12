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

#[derive(Clone, Deserialize, Serialize)]
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

pub struct Node {
    pub root: PathBuf,
    pub network: String,
    pub id: String,
    pub region: String,
    pub contacts: BTreeMap<String, Value>,
    identity: Value,
    state: State,
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
        let state = if fs::symlink_metadata(&path).is_ok() {
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
            state
        } else {
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
            }
        };
        let mut node = Self {
            root,
            network,
            id,
            region,
            contacts,
            identity,
            state,
            _lock: lock,
        };
        node.validate()?;
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
        for (id, object) in &s.archives {
            self.archive(id, object)?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let token = random()?[..32].to_owned();
        let mut meta = serde_json::to_value(&self.state).map_err(|e| e.to_string())?;
        meta["messages"] = json!({});
        let raw = bytes(&meta)?;
        codec_request(
            "Begin",
            json!({"token":token,"limits":codec_limits()}),
            &raw,
        )?;
        let operation: Result<()> = (|| {
            #[cfg(test)]
            let started = super::service::monotonic()?;
            for (id, t) in &self.state.messages {
                codec_request("Transit", json!({"token":token,"ident":id}), &bytes(t)?)?;
            }
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-encode-transits", started)?;
            #[cfg(test)]
            let started = super::service::monotonic()?;
            let result = codec(json!({"Finish":{"token":token}}), &[])?;
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-encode-finish", started)?;
            #[cfg(test)]
            let started = super::service::monotonic()?;
            atomic(
                &self.root.join("native-mesh-state.json"),
                &result["image"],
                STATE_LIMIT,
            )?;
            #[cfg(test)]
            super::service::trace_subwork("mesh-state-durable-write", started)?;
            Ok(())
        })();
        let cleanup = codec(json!({"Abort":{"token":token}}), &[]);
        operation?;
        cleanup?;
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
        let value = read(
            &self.root.join("archive").join(format!("{object}.json")),
            STATE_LIMIT,
        )?;
        require(
            digest(&value)? == object
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
        let (frame, _) = crate::contact_frame::inspect_bytes(
            raw,
            None,
            None,
            crate::contact::MAX_PAYLOAD,
            crate::contact::MAX_FRAME,
        )?;
        // One call-local lookup of complete authenticated custody, with no
        // retained proof/cache. Every later call checks its exact input again.
        let mut found = BTreeMap::<String, String>::new();
        let include = |id: &str, t: &Value| {
            if t["packet"]["body"]["node_id"] == self.id
                && t["routing"]["body"]["frame_id"] == frame.message_id.to_hex()
            {
                if let Some(destination) = t["packet"]["body"]["destination"].as_str() {
                    if destinations.iter().any(|d| d == destination) {
                        return Some((destination.to_owned(), id.to_owned()));
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
            if found.len() == destinations.len() {
                break;
            }
            let archive = self.archive(id, object)?;
            if let Some((destination, id)) = include(id, &archive["transit"]) {
                found.entry(destination).or_insert(id);
            }
        }
        require(
            self.state.messages.len() + destinations.len() - found.len() <= MAX_MESSAGES,
            "active packet capacity reached; retain old evidence",
        )?;
        let mut ids = Vec::new();
        let mut pending = Vec::new();
        for destination in destinations {
            if let Some(id) = found.get(destination) {
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
        if !pending.is_empty() {
            for (id, t) in pending {
                self.state.messages.insert(id.clone(), t);
                self.state.arrivals.push(id);
            }
            // The whole bounded typed image is durable before any batch result.
            self.save()?;
        }
        Ok(ids)
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
        let first = self
            .state
            .arrivals
            .iter()
            .filter(|id| !prior.contains(id))
            .cloned()
            .collect::<Vec<_>>();
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
            self.save()?;
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
            Self { root, configs, ids }
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
            if std::thread::panicking() {
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
