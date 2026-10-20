//! Exact mint-event facts with a private, completely reconstructed slot index.
//! Only the event-map root is native monetary commitment; the slot index is not
//! accepted as an independent proof and never arrives in wire State.
use crate::{
    codec::Id,
    merkle::{Absence, Entry, Membership},
    model::MintRecord,
    record,
    table::{Key, Record, Table},
};
use anyhow::{Context, Result, ensure};
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc;
record!(Slot {root:u32 => 0,slot:u32 => 1,event:Id => 2});
pub fn slot_key(root: u32, slot: u32) -> Id {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&((u64::from(root) << 32) | u64::from(slot)).to_be_bytes());
    Id(b)
}
impl Record for Slot {
    fn key(&self, _: Id) -> Key {
        Key::Id(slot_key(self.root, self.slot))
    }
    fn entry(&self, _: Id) -> Entry {
        Entry {
            key: slot_key(self.root, self.slot),
            value: self.event,
        }
    }
}
#[cfg(not(target_os = "zkvm"))]
pub trait Storage: std::fmt::Debug + Send + Sync {
    fn currency(&self) -> Id;
    fn home(&self) -> Id;
    fn root(&self) -> Id;
    fn count(&self) -> u64;
    fn get(&self, event: Id) -> Result<Option<MintRecord>>;
    fn slot_before_or_at(&self, key: Id) -> Result<Option<MintRecord>>;
    fn insert(&self, value: MintRecord) -> Result<Arc<dyn Storage>>;
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)>;
    fn records(&self) -> Box<dyn Iterator<Item = Result<MintRecord>> + Send + '_>;
    fn seal(&self) -> Result<Arc<dyn Storage>>;
    fn snapshot(&self) -> Result<Vec<u8>>;
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage>>;
    fn empty(&self) -> Arc<dyn Storage>;
}
#[derive(Clone)]
enum Backing {
    Full {
        events: Table<MintRecord>,
        slots: Table<Slot>,
    },
    #[cfg(not(target_os = "zkvm"))]
    Stored(Arc<dyn Storage>),
}
#[derive(Clone)]
pub struct Mints {
    currency: Id,
    home: Id,
    backing: Backing,
}
impl std::fmt::Debug for Mints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mints").field("count", &self.len()).finish()
    }
}
impl PartialEq for Mints {
    fn eq(&self, o: &Self) -> bool {
        self.currency == o.currency
            && self.home == o.home
            && match (&self.backing, &o.backing) {
                (Backing::Full { events: a, .. }, Backing::Full { events: b, .. }) => a == b,
                #[cfg(not(target_os = "zkvm"))]
                (Backing::Stored(a), Backing::Stored(b)) => {
                    a.root() == b.root() && a.count() == b.count()
                }
                #[cfg(not(target_os = "zkvm"))]
                (Backing::Stored(a), Backing::Full { events: b, .. })
                | (Backing::Full { events: b, .. }, Backing::Stored(a)) => {
                    a.count() == b.len() as u64
                        && b.commitment(self.currency, &self.tag()).ok() == Some(a.root())
                }
            }
    }
}
impl Eq for Mints {}
impl Mints {
    fn tag(&self) -> String {
        format!("{}/mints", self.home)
    }
    pub fn validate(v: &MintRecord) -> Result<()> {
        ensure!(
            v.root < crate::ROOTS && v.slot < crate::SLOTS,
            "Mint fact range"
        );
        v.owner.validate()
    }
    pub fn new(c: Id, home: Id) -> Self {
        Self {
            currency: c,
            home,
            backing: Backing::Full {
                events: Table::new(c, &format!("{home}/mints")),
                slots: Table::new(c, &format!("{home}/mint-slots-aux")),
            },
        }
    }
    pub fn from_sorted(c: Id, home: Id, values: Vec<MintRecord>) -> Result<Self> {
        let mut slots = Vec::with_capacity(values.len());
        for v in &values {
            Self::validate(v)?;
            slots.push(Slot {
                root: v.root,
                slot: v.slot,
                event: v.event,
            });
        }
        slots.sort_by_key(|s| (s.root, s.slot));
        Ok(Self {
            currency: c,
            home,
            backing: Backing::Full {
                events: Table::from_sorted(c, &format!("{home}/mints"), values)?,
                slots: Table::from_sorted(c, &format!("{home}/mint-slots-aux"), slots)?,
            },
        })
    }
    pub fn len(&self) -> u64 {
        match &self.backing {
            Backing::Full { events, .. } => events.len() as u64,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.count(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        ensure!(
            c == self.currency && tag == self.tag(),
            "Mint commitment context"
        );
        match &self.backing {
            Backing::Full { events, slots } => {
                ensure!(events.len() == slots.len(), "Mint index count");
                events.commitment(c, tag)
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => Ok(s.root()),
        }
    }
    pub fn get(&self, event: Id) -> Result<Option<MintRecord>> {
        let v = match &self.backing {
            Backing::Full { events, .. } => events.get(event).cloned(),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.get(event)?,
        };
        if let Some(v) = &v {
            Self::validate(v)?;
            ensure!(v.event == event, "Mint event lookup");
        }
        Ok(v)
    }
    pub fn contains(&self, v: &MintRecord) -> Result<bool> {
        Ok(self.get(v.event)?.as_ref() == Some(v))
    }
    fn before_or_at(&self, key: Id) -> Result<Option<MintRecord>> {
        let v = match &self.backing {
            Backing::Full { events, slots } => slots
                .before_or_at(Key::Id(key))
                .map(|s| {
                    events
                        .get(s.event)
                        .cloned()
                        .context("Mint slot has no event")
                })
                .transpose()?,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.slot_before_or_at(key)?,
        };
        if let Some(v) = &v {
            Self::validate(v)?;
            ensure!(slot_key(v.root, v.slot) <= key, "Mint slot selection bound");
        }
        Ok(v)
    }
    pub fn get_slot(&self, root: u32, slot: u32) -> Result<Option<MintRecord>> {
        ensure!(
            root < crate::ROOTS && slot < crate::SLOTS,
            "Mint lookup range"
        );
        Ok(self
            .before_or_at(slot_key(root, slot))?
            .filter(|v| v.root == root && v.slot == slot))
    }
    pub fn range_empty(&self, root: u32, lo: u32, hi: u32) -> Result<bool> {
        ensure!(
            root < crate::ROOTS && lo < hi && hi <= crate::SLOTS,
            "Mint active range"
        );
        Ok(self
            .before_or_at(slot_key(root, hi - 1))?
            .is_none_or(|v| v.root != root || v.slot < lo))
    }
    pub fn insert(&mut self, value: MintRecord) -> Result<()> {
        Self::validate(&value)?;
        ensure!(
            self.get(value.event)?.is_none() && self.get_slot(value.root, value.slot)?.is_none(),
            "duplicate Mint event/global slot"
        );
        match &mut self.backing {
            Backing::Full { events, slots } => {
                let mut e = events.clone();
                let mut s = slots.clone();
                s.insert(Slot {
                    root: value.root,
                    slot: value.slot,
                    event: value.event,
                })?;
                e.insert(value)?;
                *events = e;
                *slots = s;
                Ok(())
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                let n = s.insert(value)?;
                *s = n;
                Ok(())
            }
        }
    }
    pub fn records(&self) -> Box<dyn Iterator<Item = Result<MintRecord>> + '_> {
        let iter: Box<dyn Iterator<Item = Result<MintRecord>> + '_> = match &self.backing {
            Backing::Full { events, .. } => Box::new(events.iter().cloned().map(Ok)),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.records(),
        };
        Box::new(iter.map(|v| {
            let v = v?;
            Self::validate(&v)?;
            Ok(v)
        }))
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        self.records()
            .map(|v| Ok(v?.entry(self.currency)))
            .collect()
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        match &self.backing {
            Backing::Full { events, .. } => events.witness(key),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.access(key)?.0.context("Mint event absent"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        match &self.backing {
            Backing::Full { events, .. } => events.query(key),
            Backing::Stored(s) => s.access(key),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(self, s: Arc<dyn Storage>) -> Result<Self> {
        ensure!(
            self.is_empty()
                && s.count() == 0
                && s.currency() == self.currency
                && s.home() == self.home
                && self.commitment(self.currency, &self.tag())? == s.root(),
            "Mint exact empty storage"
        );
        Ok(Self {
            backing: Backing::Stored(s),
            ..self
        })
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn seal(&mut self) -> Result<()> {
        if let Backing::Stored(s) = &mut self.backing {
            let n = s.seal()?;
            *s = n;
        }
        Ok(())
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        match &self.backing {
            Backing::Stored(s) => s.snapshot(),
            _ => anyhow::bail!("Mint storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical(&self, b: &[u8]) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Ok(Self {
                backing: Backing::Stored(s.historical(b)?),
                ..self.clone()
            }),
            _ => anyhow::bail!("Mint storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Self::new(self.currency, self.home).on_empty_storage(s.empty()),
            _ => anyhow::bail!("Mint storage unavailable"),
        }
    }
}
impl serde::Serialize for Mints {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(
            usize::try_from(self.len()).map_err(serde::ser::Error::custom)?,
        ))?;
        for v in self.records() {
            seq.serialize_element(&v.map_err(serde::ser::Error::custom)?)?;
        }
        seq.end()
    }
}
impl<C> minicbor::Encode<C> for Mints {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len())?;
        for v in self.records() {
            v.map_err(|_| minicbor::encode::Error::message("Mint storage read failed"))?
                .encode(e, c)?;
        }
        Ok(())
    }
}
