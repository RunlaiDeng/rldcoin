//! Both observations derive from complete native Mint execution. An auxiliary
//! slot root is never peer monetary evidence or a guest-input authority.
use crate::{
    object_store::{ObjectStatus, Objects},
    runtime::Initial,
    typed_paths::Paths,
};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Blob, Id, decode, encode},
    merkle::{Absence, Membership},
    mints::{Slot, Storage, slot_key},
    model::MintRecord,
    record,
};
use std::{path::Path, sync::Arc};
const FORMAT: &str = "RLD-MINT-FACTS-DISK-1";
record!(Snapshot{format:String => 0,events:Blob => 1,slots:Blob => 2});
#[derive(Clone)]
pub(crate) struct MintStore {
    events: Arc<Paths<MintRecord>>,
    slots: Arc<Paths<Slot>>,
}
impl std::fmt::Debug for MintStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintStore")
            .field("events", &self.events)
            .field("slots", &self.slots)
            .finish()
    }
}
impl MintStore {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let c = initial.currency.id();
        let d = initial.genesis.configuration.domain;
        let g = rld_protocol::state::genesis_id(c, &initial.genesis);
        let objects = Objects::open(path, &encode(&(FORMAT, c, d, g)))?;
        Ok(Self {
            events: Arc::new(Paths::on_objects(objects.clone(), initial)?),
            slots: Arc::new(Paths::on_objects(objects, initial)?),
        })
    }
    pub(crate) fn status(&self) -> Result<ObjectStatus> {
        self.events.status()
    }
    fn counts(&self) -> Result<()> {
        ensure!(
            self.events.count() == self.slots.count(),
            "Mint primary/auxiliary count mismatch"
        );
        Ok(())
    }
}
impl Storage for MintStore {
    fn currency(&self) -> Id {
        self.events.currency()
    }
    fn home(&self) -> Id {
        self.events.home()
    }
    fn root(&self) -> Id {
        self.events.root()
    }
    fn count(&self) -> u64 {
        self.events.count()
    }
    fn get(&self, event: Id) -> Result<Option<MintRecord>> {
        self.counts()?;
        self.events.get(event)
    }
    fn slot_before_or_at(&self, key: Id) -> Result<Option<MintRecord>> {
        self.counts()?;
        let Some(slot) = self.slots.at_or_before(key)? else {
            return Ok(None);
        };
        let value = self
            .events
            .get(slot.event)?
            .context("indexed Mint event missing")?;
        ensure!(
            value.root == slot.root
                && value.slot == slot.slot
                && slot_key(slot.root, slot.slot) <= key,
            "Mint slot/event binding"
        );
        Ok(Some(value))
    }
    fn insert(&self, value: MintRecord) -> Result<Arc<dyn Storage>> {
        self.counts()?;
        rld_protocol::mints::Mints::validate(&value)?;
        ensure!(
            self.events.get(value.event)?.is_none()
                && self.slots.get(slot_key(value.root, value.slot))?.is_none(),
            "duplicate Mint event/slot"
        );
        let slots = self.slots.insert_path(Slot {
            root: value.root,
            slot: value.slot,
            event: value.event,
        })?;
        let events = self.events.insert_path(value)?;
        let next = Self { events, slots };
        next.counts()?;
        Ok(Arc::new(next))
    }
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        self.counts()?;
        self.events.access(key)
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<MintRecord>> + Send + '_> {
        self.events.records()
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
        self.counts()?;
        let events = self.events.seal_path()?;
        let slots = self.slots.seal_path()?;
        Ok(Arc::new(Self { events, slots }))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        self.counts()?;
        let bytes = encode(&Snapshot {
            format: FORMAT.into(),
            events: Blob(self.events.snapshot()?),
            slots: Blob(self.slots.snapshot()?),
        });
        ensure!(bytes.len() <= 2048, "Mint pair snapshot bound");
        Ok(bytes)
    }
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage>> {
        let s: Snapshot = decode(b, 2048)?;
        ensure!(s.format == FORMAT, "Mint observation format");
        let next = Self {
            events: self.events.historical_path(&s.events.0)?,
            slots: self.slots.historical_path(&s.slots.0)?,
        };
        next.counts()?;
        Ok(Arc::new(next))
    }
    fn empty(&self) -> Arc<dyn Storage> {
        Arc::new(Self {
            events: self.events.empty_path(),
            slots: self.slots.empty_path(),
        })
    }
}
