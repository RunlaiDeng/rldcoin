//! Only ordinary native execution derives these insert/replace observations.
use crate::{
    object_store::Objects,
    runtime::Initial,
    typed_paths::{Paths, Value},
};
use anyhow::Result;
use rld_protocol::{
    codec::{Id, encode},
    merkle::{Absence, Membership},
    model::{Delegation, Family, Service},
    mutable::Storage,
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
    fn replace(&self, value: T) -> Result<Arc<dyn Storage<T>>> {
        Ok(self.replace_path(value)?)
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
pub(crate) fn initialize(root: &Path, initial: &Initial, s: &mut State) -> Result<Arc<Objects>> {
    let c = initial.currency.id();
    let d = initial.genesis.configuration.domain;
    let g = rld_protocol::state::genesis_id(c, &initial.genesis);
    let objects = Objects::open(
        &root.join("service-index"),
        &encode(&("RLD-SERVICE-STATE-DISK-1", c, d, g)),
    )?;
    s.services = s
        .services
        .clone()
        .on_empty_storage(Arc::new(Paths::<Service>::on_objects(
            objects.clone(),
            initial,
        )?))?;
    s.coupon_uses =
        s.coupon_uses
            .clone()
            .on_empty_storage(Arc::new(Paths::<Delegation>::on_objects(
                objects.clone(),
                initial,
            )?))?;
    s.families = s
        .families
        .clone()
        .on_empty_storage(Arc::new(Paths::<Family>::on_objects(
            objects.clone(),
            initial,
        )?))?;
    Ok(objects)
}
