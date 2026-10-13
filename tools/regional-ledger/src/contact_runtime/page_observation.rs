//! Bounded facts from one actual receive selection, never scheduling inputs.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

thread_local! {
    static LAST: std::cell::RefCell<Option<Value>> = const { std::cell::RefCell::new(None) };
}

pub(super) struct Inputs<'a> {
    pub node: &'a str,
    pub limit: usize,
    pub after: Option<&'a str>,
    pub seen: &'a [String],
    pub arrivals: &'a [String],
    pub messages: &'a BTreeMap<String, Value>,
    pub archives: &'a BTreeMap<String, String>,
    pub rotated_ids: &'a [String],
}

pub(super) struct Observation {
    node: String,
    value: Value,
    watched: Vec<Value>,
    first: Vec<String>,
    visited: usize,
    returned: Vec<Value>,
    excluded: usize,
    nonlocal: usize,
    archive_scanned: usize,
}

fn classify(transit: &Value, node: &str) -> &'static str {
    if transit.is_null() {
        "receipt-only"
    } else if transit["packet"]["body"]["destination"] == node {
        "local"
    } else {
        "nonlocal"
    }
}

pub(super) fn begin(inputs: Inputs<'_>) -> Result<Option<Observation>> {
    LAST.with(|last| *last.borrow_mut() = None);
    let Some(watch) = super::page_watch::snapshot_before_page(inputs.node) else {
        return Ok(None);
    };
    let targets = watch["targets"]
        .as_array()
        .ok_or("page watch targets absent")?;
    require(targets.len() <= 8, "page watch target bound")?;
    let seen = inputs.seen.iter().collect::<BTreeSet<_>>();
    let mut ranks = BTreeMap::new();
    if !targets.is_empty() {
        for arrival in inputs.arrivals {
            if !seen.contains(arrival)
                && inputs
                    .messages
                    .get(arrival)
                    .is_some_and(|transit| transit["packet"]["body"]["destination"] == inputs.node)
            {
                ranks.insert(arrival.as_str(), ranks.len());
            }
        }
    }
    let mut watched = Vec::new();
    for target in targets {
        let id = target["packet_id"]
            .as_str()
            .ok_or("page watch packet absent")?;
        let active = inputs.messages.get(id);
        watched.push(json!({
            "target":target,"active_present":active.is_some(),
            "archive_present":inputs.archives.contains_key(id),
            "seen":inputs.seen.iter().any(|seen|seen==id),
            "arrivals_index":inputs.arrivals.iter().position(|arrival|arrival==id),
            "active_unseen_local_rank":ranks.get(id),
            "rotated_union_position":inputs.rotated_ids.iter().position(|candidate|candidate==id),
            "active_classification":active.map(|t|classify(t,inputs.node)),
            "active_frame_matches":active.map(|t|t["routing"]["body"]["frame_id"]==target["frame_id"]),
            "archive_priority_inspected":false,"archive_classification":"not-read",
            "merged_positions":[],"visited_positions":[],"result_indices":[]
        }));
    }
    Ok(Some(Observation {
        node: inputs.node.into(),
        value: json!({"watch":watch,"node_id":inputs.node,"limit":inputs.limit,
            "after":inputs.after,"priority_enabled":!inputs.seen.is_empty(),
            "active_count":inputs.messages.len(),"archive_count":inputs.archives.len(),
            "union_count":inputs.rotated_ids.len(),"seen_count":inputs.seen.len(),
            "active_priority":[],"archive_priority":[],"first":[],
            "archive_priority_end":if inputs.seen.is_empty(){"disabled"}else{"exhausted"},
            "archive_priority_last":null,"stop":"exhausted",
            "ledger_authority":false,"seen_is_native_acceptance":false}),
        watched,
        first: vec![],
        visited: 0,
        returned: vec![],
        excluded: 0,
        nonlocal: 0,
        archive_scanned: 0,
    }))
}

impl Observation {
    pub(super) fn archive(&mut self, id: &str, transit: &Value, priority_scan: bool) {
        if priority_scan {
            self.archive_scanned += 1;
            self.value["archive_priority_last"] = json!(id);
        }
        for row in &mut self.watched {
            if row["target"]["packet_id"] == id {
                if priority_scan {
                    row["archive_priority_inspected"] = json!(true);
                }
                row["archive_classification"] = json!(classify(transit, &self.node));
                row["archive_frame_matches"] = json!(
                    !transit.is_null()
                        && transit["routing"]["body"]["frame_id"] == row["target"]["frame_id"]
                );
            }
        }
    }
    pub(super) fn archive_priority_full(&mut self) {
        self.value["archive_priority_end"] = json!("two-local-candidates");
    }
    pub(super) fn priority(&mut self, active: &[String], archived: &[String], first: &[String]) {
        self.first = first.to_vec();
        self.value["active_priority"] = json!(active);
        self.value["archive_priority"] = json!(archived);
        self.value["first"] = json!(first);
    }
    pub(super) fn order(&mut self, ids: &[String]) {
        for row in &mut self.watched {
            let positions = ids
                .iter()
                .enumerate()
                .filter_map(|(n, id)| (row["target"]["packet_id"] == *id).then_some(n))
                .collect::<Vec<_>>();
            row["merged_positions"] = json!(positions);
        }
    }
    pub(super) fn visit(&mut self, id: &str) {
        for row in &mut self.watched {
            if row["target"]["packet_id"] == id {
                row["visited_positions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(self.visited));
            }
        }
        self.visited += 1;
    }
    pub(super) fn skip(&mut self, id: &str, excluded: bool) {
        if excluded {
            self.excluded += 1
        } else {
            self.nonlocal += 1
        }
        for row in &mut self.watched {
            if row["target"]["packet_id"] == id {
                row["skip"] = json!(if excluded {
                    "excluded-nonlocal-archive"
                } else {
                    "nonlocal-or-receipt-only"
                });
            }
        }
    }
    pub(super) fn returned(&mut self, id: &str, active: bool, seen: bool) {
        for row in &mut self.watched {
            if row["target"]["packet_id"] == id {
                row["result_indices"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(self.returned.len()));
            }
        }
        self.returned.push(
            json!({"packet_id":id,"source":if active{"active"}else{"archive"},
            "seen":seen,"role":if self.visited<=self.first.len(){"priority"}else{"fallback"},
            "merged_position":self.visited-1}),
        );
    }
    pub(super) fn limit_reached(&mut self) {
        self.value["stop"] = json!("result-limit");
    }
    pub(super) fn finish(mut self) {
        self.value["watched"] = json!(self.watched);
        self.value["returned"] = json!(self.returned);
        self.value["processed_candidates"] = json!(self.visited);
        self.value["next_stop_index"] = json!(self.visited);
        self.value["excluded_skips"] = json!(self.excluded);
        self.value["nonlocal_skips"] = json!(self.nonlocal);
        self.value["archive_priority_scanned"] = json!(self.archive_scanned);
        LAST.with(|last| *last.borrow_mut() = Some(self.value));
    }
}

pub(super) fn take() -> Option<Value> {
    LAST.with(|last| last.borrow_mut().take())
}
