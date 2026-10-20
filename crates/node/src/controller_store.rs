//! Immutable controller and conflict-fact paths from complete native replay.
use crate::{object_store::Objects, runtime::Initial, typed_paths::Paths};
use anyhow::Result;
use rld_protocol::{codec::encode, model::Controller, state::State};
use std::{path::Path, sync::Arc};
pub(crate) fn initialize(
    root: &Path,
    initial: &Initial,
    state: &mut State,
) -> Result<Arc<Objects>> {
    let c = initial.currency.id();
    let d = initial.genesis.configuration.domain;
    let g = rld_protocol::state::genesis_id(c, &initial.genesis);
    let objects = Objects::open(
        &root.join("controller-index"),
        &encode(&("RLD-CONTROLLER-STATE-DISK-1", c, d, g)),
    )?;
    state.controllers =
        state
            .controllers
            .clone()
            .on_empty_storage(Arc::new(Paths::<Controller>::on_objects(
                objects.clone(),
                initial,
            )?))?;
    state.incidents = state.incidents.clone().on_empty_storage(Arc::new(Paths::<
        rld_protocol::incidents::Value,
    >::on_objects(
        objects.clone(),
        initial,
    )?))?;
    Ok(objects)
}
