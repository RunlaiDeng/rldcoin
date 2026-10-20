//! Append-only definition paths; only native genesis/replay derives roots.
use crate::{
    object_store::Objects,
    runtime::Initial,
    typed_paths::{Paths, Value},
};
use anyhow::{Result, ensure};
use rld_protocol::{
    codec::{Id, encode},
    merkle::{Absence, Membership},
    permanent::{Permanent, Storage},
    state::State,
};
use std::{path::Path, sync::Arc};

impl<T: Value> Storage<T> for Paths<T> {
    fn currency(&self) -> Id {
        Paths::currency(self)
    }
    fn tag(&self) -> &str {
        self.native_tag()
    }
    fn root(&self) -> Id {
        Paths::root(self)
    }
    fn count(&self) -> u64 {
        Paths::count(self)
    }
    fn get(&self, key: Id) -> Result<Option<T>> {
        Paths::get(self, key)
    }
    fn insert(&self, value: T) -> Result<Arc<dyn Storage<T>>> {
        Ok(self.insert_path(value)?)
    }
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        Paths::access(self, key)
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_> {
        Paths::records(self)
    }
    fn seal(&self) -> Result<Arc<dyn Storage<T>>> {
        Ok(self.seal_path()?)
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        Paths::snapshot(self)
    }
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage<T>>> {
        Ok(self.historical_path(b)?)
    }
    fn empty(&self) -> Arc<dyn Storage<T>> {
        self.empty_path()
    }
}

fn seed<T: crate::typed_paths::Value>(
    original: &Permanent<T>,
    mut empty: Permanent<T>,
    c: Id,
    tag: &str,
) -> Result<Permanent<T>> {
    ensure!(
        original.is_complete() && empty.is_complete() && empty.is_empty(),
        "definition genesis needs complete source and empty backing"
    );
    for record in original.records() {
        empty.insert(record?)?;
    }
    ensure!(
        empty.len() == original.len()
            && empty.commitment(c, tag)? == original.commitment(c, tag)?,
        "definition genesis reconstruction mismatch"
    );
    empty.seal()?;
    Ok(empty)
}
pub(crate) fn seed_genesis(
    state: &State,
    covers: rld_protocol::permanent::Permanent<rld_protocol::model::Cover>,
    policies: rld_protocol::permanent::Permanent<rld_protocol::model::FeePolicy>,
) -> Result<(
    rld_protocol::permanent::Permanent<rld_protocol::model::Cover>,
    rld_protocol::permanent::Permanent<rld_protocol::model::FeePolicy>,
)> {
    ensure!(state.sequence == 0, "definition seeding is genesis-only");
    let c = state.currency;
    let d = state.domain;
    Ok((
        seed(&state.covers, covers, c, &format!("{d}/covers"))?,
        seed(
            &state.fee_policies,
            policies,
            c,
            &format!("{d}/fee_policies"),
        )?,
    ))
}
pub(crate) fn initialize(
    root: &Path,
    initial: &Initial,
    state: &mut State,
) -> Result<Arc<Objects>> {
    let c = initial.currency.id();
    let d = initial.genesis.configuration.domain;
    ensure!(
        state.currency == c && state.domain == d,
        "definition genesis context"
    );
    let g = rld_protocol::state::genesis_id(c, &initial.genesis);
    let objects = Objects::open(
        &root.join("definition-index"),
        &encode(&("RLD-DEFINITION-DISK-1", c, d, g)),
    )?;
    let covers =
        Permanent::new(c, &format!("{d}/covers")).on_empty_storage(Arc::new(Paths::<
            rld_protocol::model::Cover,
        >::on_objects(
            objects.clone(),
            initial,
        )?))?;
    let policies =
        Permanent::new(c, &format!("{d}/fee_policies")).on_empty_storage(Arc::new(Paths::<
            rld_protocol::model::FeePolicy,
        >::on_objects(
            objects.clone(),
            initial,
        )?))?;
    let (covers, policies) = seed_genesis(state, covers, policies)?;
    state.covers = covers;
    state.fee_policies = policies;
    Ok(objects)
}
