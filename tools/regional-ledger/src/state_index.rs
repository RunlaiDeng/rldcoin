//! Incremental computation of the unchanged V1 ordered Merkle commitment.
//! One private process-local witness retains exact typed records and levels.
//! Every invocation audits and compares all current records; no stored digest,
//! ledger, trust context or proof can initialize native value execution.
use super::*;
use crate::state_proof::{self as proof, Collection, Commitment, IndexRoot, Value};
use std::sync::{Arc, Mutex};

static WITNESS: Mutex<Option<StateIndex>> = Mutex::new(None);
const RECORD_OVERHEAD: usize = 256;

#[derive(Clone)]
struct Entry {
    value: Value,
    leaf: Hash,
    retained_bytes: usize,
}
#[derive(Clone, Default)]
struct Index {
    entries: BTreeMap<Hash, Arc<Entry>>,
    levels: Vec<Vec<Hash>>,
    retained_bytes: usize,
}
struct StateIndex {
    indexes: [Index; 3],
}
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Cost {
    pub leaf_hashes: usize,
    pub reused_leaves: usize,
    pub branch_hashes: usize,
    pub reused_branches: usize,
    pub retained_bytes: usize,
    pub witness_retained: bool,
    pub uncached_fallback: bool,
}
pub(crate) struct Prepared {
    pub values: Vec<(Hash, Value)>,
    pub levels: Vec<Vec<Hash>>,
}
enum Record<'a> {
    Coins(&'a Coin),
    Exports(&'a Export),
    Imports(&'a Hash),
}
impl Record<'_> {
    fn matches(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Coins(a), Value::Coins(b)) => *a == b,
            (Self::Exports(a), Value::Exports(b)) => *a == b,
            (Self::Imports(a), Value::Imports(b)) => *a == b,
            _ => false,
        }
    }
    fn owned(&self) -> Value {
        match self {
            Self::Coins(v) => Value::Coins((*v).clone()),
            Self::Exports(v) => Value::Exports((*v).clone()),
            Self::Imports(v) => Value::Imports(**v),
        }
    }
}
fn position(kind: Collection) -> usize {
    match kind {
        Collection::Coins => 0,
        Collection::Exports => 1,
        Collection::Imports => 2,
    }
}
fn records(ledger: &Ledger, kind: Collection) -> Box<dyn Iterator<Item = (Hash, Record<'_>)> + '_> {
    match kind {
        Collection::Coins => Box::new(ledger.coins.iter().map(|(k, v)| (*k, Record::Coins(v)))),
        Collection::Exports => {
            Box::new(ledger.exports.iter().map(|(k, v)| (*k, Record::Exports(v))))
        }
        Collection::Imports => {
            Box::new(ledger.imports.iter().map(|(k, v)| (*k, Record::Imports(v))))
        }
    }
}
impl Index {
    fn refresh(
        previous: Option<&Self>,
        ledger: &Ledger,
        kind: Collection,
        budget: &mut usize,
        cost: &mut Cost,
    ) -> Result<Option<Self>> {
        let mut next = Self::default();
        for (key, record) in records(ledger, kind) {
            let old = previous.and_then(|p| p.entries.get(&key));
            let entry = if let Some(entry) = old.filter(|e| record.matches(&e.value)) {
                cost.reused_leaves += 1;
                Arc::clone(entry)
            } else {
                let value = record.owned();
                let retained_bytes = serde_json::to_vec(&value)
                    .map_err(|e| e.to_string())?
                    .len()
                    .checked_add(RECORD_OVERHEAD)
                    .ok_or("state index retention overflow")?;
                if retained_bytes > MAX_BYTES.saturating_sub(*budget) {
                    return Ok(None);
                }
                cost.leaf_hashes += 1;
                Arc::new(Entry {
                    leaf: value.leaf(kind, key)?,
                    value,
                    retained_bytes,
                })
            };
            *budget = budget
                .checked_add(entry.retained_bytes)
                .ok_or("state index retention overflow")?;
            if *budget > MAX_BYTES {
                return Ok(None);
            }
            next.retained_bytes += entry.retained_bytes;
            next.entries.insert(key, entry);
        }
        next.levels
            .push(next.entries.values().map(|e| e.leaf).collect());
        while next.levels.last().is_some_and(|v| v.len() > 1) {
            let depth = next.levels.len() - 1;
            let mut parents = Vec::new();
            for (index, pair) in next.levels[depth].chunks(2).enumerate() {
                // V1 binds collection, level and both exact child hashes.
                // Position alone or an unchanged parent digest is insufficient.
                let reused = previous.and_then(|p| {
                    let old_children = p.levels.get(depth)?.chunks(2).nth(index)?;
                    (old_children == pair)
                        .then(|| p.levels.get(depth + 1)?.get(index).copied())
                        .flatten()
                });
                let parent = if let Some(hash) = reused {
                    cost.reused_branches += 1;
                    hash
                } else {
                    cost.branch_hashes += 1;
                    proof::branch(
                        kind,
                        depth,
                        pair[0],
                        match pair.get(1) {
                            Some(h) => *h,
                            None => proof::padding(kind, depth)?,
                        },
                    )?
                };
                parents.push(parent);
            }
            next.levels.push(parents);
        }
        let bytes = next.levels.iter().map(Vec::len).sum::<usize>() * 32;
        *budget = budget
            .checked_add(bytes)
            .ok_or("state index retention overflow")?;
        if *budget > MAX_BYTES {
            return Ok(None);
        }
        next.retained_bytes += bytes;
        Ok(Some(next))
    }
    fn root(&self, kind: Collection) -> Result<IndexRoot> {
        Ok(IndexRoot {
            entries: self.entries.len() as u64,
            tree: match self.levels.last().and_then(|v| v.first()) {
                Some(hash) => *hash,
                None => proof::empty(kind)?,
            },
        })
    }
    fn prepared(&self) -> Prepared {
        Prepared {
            values: self
                .entries
                .iter()
                .map(|(k, e)| (*k, e.value.clone()))
                .collect(),
            levels: self.levels.clone(),
        }
    }
}
fn cold_prepared(ledger: &Ledger, kind: Collection) -> Result<Prepared> {
    let values: Vec<_> = records(ledger, kind).map(|(k, r)| (k, r.owned())).collect();
    let levels = proof::levels(
        kind,
        values
            .iter()
            .map(|(k, v)| v.leaf(kind, *k))
            .collect::<Result<Vec<_>>>()?,
    )?;
    Ok(Prepared { values, levels })
}
fn calculate(
    witness: &mut Option<StateIndex>,
    ledger: &Ledger,
    selected: Option<Collection>,
) -> Result<(Commitment, Option<Prepared>, Cost)> {
    // Conservation and every exact record are checked before any reuse. This
    // pure hashing witness supplies neither native execution nor trust rights.
    ledger.audit()?;
    let mut indexes = Vec::new();
    let mut budget = 0;
    let mut cost = Cost::default();
    for kind in [Collection::Coins, Collection::Exports, Collection::Imports] {
        let old = witness.as_ref().map(|s| &s.indexes[position(kind)]);
        let Some(index) = Index::refresh(old, ledger, kind, &mut budget, &mut cost)? else {
            // Exceeding optional retention never changes the accepted state
            // commitment, proof dialect, ledger bounds or cold validation.
            let state = Commitment::from_ledger_uncached(ledger)?;
            let prepared = selected.map(|k| cold_prepared(ledger, k)).transpose()?;
            *witness = None;
            let mut fallback = Cost {
                uncached_fallback: true,
                ..cost
            };
            for kind in [Collection::Coins, Collection::Exports, Collection::Imports]
                .into_iter()
                .chain(selected)
            {
                let mut width = records(ledger, kind).count();
                fallback.leaf_hashes += width;
                while width > 1 {
                    width = width.div_ceil(2);
                    fallback.branch_hashes += width;
                }
            }
            return Ok((state, prepared, fallback));
        };
        indexes.push(index);
    }
    let indexes: [Index; 3] = indexes.try_into().map_err(|_| "state index collections")?;
    let state = Commitment {
        format: proof::FORMAT.into(),
        coins: indexes[0].root(Collection::Coins)?,
        exports: indexes[1].root(Collection::Exports)?,
        imports: indexes[2].root(Collection::Imports)?,
        minted: ledger.minted,
        received: ledger.received,
    };
    state.hash()?;
    let prepared = selected.map(|k| indexes[position(k)].prepared());
    cost.retained_bytes = budget;
    cost.witness_retained = true;
    *witness = Some(StateIndex { indexes });
    Ok((state, prepared, cost))
}
pub(crate) fn compute(
    ledger: &Ledger,
    selected: Option<Collection>,
) -> Result<(Commitment, Option<Prepared>, Cost)> {
    let mut witness = match WITNESS.lock() {
        Ok(witness) => witness,
        Err(error) => {
            let mut witness = error.into_inner();
            *witness = None;
            WITNESS.clear_poison();
            witness
        }
    };
    calculate(&mut witness, ledger, selected)
}

#[cfg(test)]
#[path = "state_index_tests.rs"]
mod tests;
