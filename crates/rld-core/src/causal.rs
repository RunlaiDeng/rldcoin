use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{CausalEnvelope, TransportClass};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalDecision {
    Accepted,
    PendingMissingParents(Vec<String>),
    Duplicate,
    Quarantined(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CausalFirewall {
    accepted: BTreeMap<String, CausalEnvelope>,
    pending: BTreeMap<String, CausalEnvelope>,
    object_versions: BTreeMap<String, u64>,
    quarantined: BTreeMap<String, String>,
}

impl CausalFirewall {
    pub fn submit(&mut self, envelope: CausalEnvelope) -> CausalDecision {
        if self.accepted.contains_key(&envelope.envelope_id)
            || self.pending.contains_key(&envelope.envelope_id)
        {
            return CausalDecision::Duplicate;
        }
        if envelope.transport == TransportClass::ChronologyUnsafe {
            let reason = "chronology-unsafe transports cannot carry real RLD".to_owned();
            self.quarantined
                .insert(envelope.envelope_id.clone(), reason.clone());
            return CausalDecision::Quarantined(reason);
        }
        if envelope
            .parent_ids
            .iter()
            .any(|id| id == &envelope.envelope_id)
        {
            let reason = "causal envelope references itself".to_owned();
            self.quarantined
                .insert(envelope.envelope_id.clone(), reason.clone());
            return CausalDecision::Quarantined(reason);
        }

        self.pending
            .insert(envelope.envelope_id.clone(), envelope.clone());
        if self.graph_has_cycle() {
            self.pending.remove(&envelope.envelope_id);
            let reason = "causal cycle detected".to_owned();
            self.quarantined
                .insert(envelope.envelope_id.clone(), reason.clone());
            return CausalDecision::Quarantined(reason);
        }

        let missing = envelope
            .parent_ids
            .iter()
            .filter(|parent| !self.accepted.contains_key(*parent))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return CausalDecision::PendingMissingParents(missing);
        }

        if let Some(version) = self.object_versions.get(&envelope.object_id) {
            if envelope.object_version <= *version {
                self.pending.remove(&envelope.envelope_id);
                let reason = format!(
                    "object version {} is not newer than accepted version {version}",
                    envelope.object_version
                );
                self.quarantined
                    .insert(envelope.envelope_id.clone(), reason.clone());
                return CausalDecision::Quarantined(reason);
            }
        }
        self.accept(envelope);
        self.promote_pending();
        CausalDecision::Accepted
    }

    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn quarantined_count(&self) -> usize {
        self.quarantined.len()
    }

    fn accept(&mut self, envelope: CausalEnvelope) {
        self.pending.remove(&envelope.envelope_id);
        self.object_versions
            .insert(envelope.object_id.clone(), envelope.object_version);
        self.accepted.insert(envelope.envelope_id.clone(), envelope);
    }

    fn promote_pending(&mut self) {
        loop {
            let ready = self
                .pending
                .values()
                .filter(|envelope| {
                    envelope
                        .parent_ids
                        .iter()
                        .all(|parent| self.accepted.contains_key(parent))
                })
                .cloned()
                .collect::<Vec<_>>();
            if ready.is_empty() {
                break;
            }
            for envelope in ready {
                let is_newer = self
                    .object_versions
                    .get(&envelope.object_id)
                    .map(|version| envelope.object_version > *version)
                    .unwrap_or(true);
                if is_newer {
                    self.accept(envelope);
                } else {
                    self.pending.remove(&envelope.envelope_id);
                    self.quarantined.insert(
                        envelope.envelope_id,
                        "pending envelope conflicts with accepted object version".into(),
                    );
                }
            }
        }
    }

    fn graph_has_cycle(&self) -> bool {
        let graph = self
            .accepted
            .iter()
            .chain(self.pending.iter())
            .map(|(id, envelope)| (id.clone(), envelope.parent_ids.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        graph
            .keys()
            .any(|id| visit(id, &graph, &mut visiting, &mut visited))
    }
}

fn visit(
    id: &str,
    graph: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if visiting.contains(id) {
        return true;
    }
    if visited.contains(id) {
        return false;
    }
    visiting.insert(id.to_owned());
    if let Some(parents) = graph.get(id) {
        for parent in parents {
            if graph.contains_key(parent) && visit(parent, graph, visiting, visited) {
                return true;
            }
        }
    }
    visiting.remove(id);
    visited.insert(id.to_owned());
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(id: &str, parents: &[&str], version: u64) -> CausalEnvelope {
        CausalEnvelope {
            envelope_id: id.into(),
            parent_ids: parents.iter().map(|value| value.to_string()).collect(),
            object_id: "coin".into(),
            object_version: version,
            source_checkpoint: "checkpoint".into(),
            transport: TransportClass::CausalFtl,
            payload_hash: "payload".into(),
        }
    }

    #[test]
    fn missing_parent_waits_then_promotes() {
        let mut firewall = CausalFirewall::default();
        assert!(matches!(
            firewall.submit(envelope("b", &["a"], 2)),
            CausalDecision::PendingMissingParents(_)
        ));
        assert_eq!(
            firewall.submit(envelope("a", &[], 1)),
            CausalDecision::Accepted
        );
        assert_eq!(firewall.accepted_count(), 2);
    }

    #[test]
    fn cycle_is_quarantined() {
        let mut firewall = CausalFirewall::default();
        let _ = firewall.submit(envelope("a", &["b"], 1));
        assert!(matches!(
            firewall.submit(envelope("b", &["a"], 2)),
            CausalDecision::Quarantined(_)
        ));
    }
}
