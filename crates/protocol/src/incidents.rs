//! Immutable conflict records. Wire order remains (family,anchor); native
//! membership remains keyed by the original RLD-INCIDENT-KEY hash.
use crate::{
    codec::Id,
    merkle::{Entry, Membership},
    model::Incident,
    permanent::{Permanent, access::Access},
    record,
    table::{Key, Record},
};
use anyhow::{Result, ensure};
record!(Value{incident:Incident => 0});
impl Record for Value {
    fn key(&self, c: Id) -> Key {
        Key::Id(self.incident.entry(c).key)
    }
    fn entry(&self, c: Id) -> Entry {
        self.incident.entry(c)
    }
}
pub fn key(c: Id, family: Id, anchor: Id) -> Id {
    crate::codec::hash("RLD-INCIDENT-KEY", c, &(family, anchor))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incidents {
    currency: Id,
    home: Id,
    inner: Permanent<Value>,
}
impl Incidents {
    pub fn new(c: Id, home: Id) -> Self {
        Self {
            currency: c,
            home,
            inner: Permanent::new(c, &format!("{home}/incidents")),
        }
    }
    pub fn from_sorted(c: Id, home: Id, values: Vec<Incident>) -> Result<Self> {
        ensure!(
            values
                .windows(2)
                .all(|w| (w[0].family, w[0].anchor) < (w[1].family, w[1].anchor)),
            "incident canonical tuple order/duplicate"
        );
        let mut values: Vec<_> = values
            .into_iter()
            .map(|incident| Value { incident })
            .collect();
        values.sort_by_key(|v| v.entry(c).key);
        Ok(Self {
            currency: c,
            home,
            inner: Permanent::from_sorted(c, &format!("{home}/incidents"), values)?,
        })
    }
    pub fn len(&self) -> u64 {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        ensure!(
            c == self.currency && tag == format!("{}/incidents", self.home),
            "incident context"
        );
        self.inner.commitment(c, tag)
    }
    pub fn known(&self, family: Id, anchor: Id) -> Result<bool> {
        let Some(v) = self.inner.get(key(self.currency, family, anchor))? else {
            return Ok(false);
        };
        ensure!(
            v.incident.family == family && v.incident.anchor == anchor,
            "incident lookup tuple binding"
        );
        Ok(true)
    }
    pub fn insert(&mut self, incident: Incident) -> Result<()> {
        self.inner.insert(Value { incident })
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        self.inner.entries(self.currency)
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        self.inner.witness(key)
    }
    pub(crate) fn from_access(c: Id, home: Id, a: &Access<Value>) -> Result<Self> {
        Ok(Self {
            currency: c,
            home,
            inner: Permanent::from_access(c, &format!("{home}/incidents"), a)?,
        })
    }
    pub(crate) fn finish_access(&self) -> Result<()> {
        self.inner.finish_access()
    }
    // Complete fallback/export preserves the original tuple wire order. It may
    // materialize that bounded array; normal execution and access proofs do not.
    fn canonical_records(&self) -> Result<Vec<Incident>> {
        struct Count(usize);
        impl minicbor::encode::Write for Count {
            type Error = std::io::Error;
            fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
                self.0 = self
                    .0
                    .checked_add(b.len())
                    .filter(|n| *n <= 1024 * 1024 * 1024)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "complete incident input capacity",
                        )
                    })?;
                Ok(())
            }
        }
        ensure!(
            self.is_complete(),
            "partial incidents cannot export complete records"
        );
        let mut count = Count(9);
        let mut values = vec![];
        for v in self.inner.records() {
            let value = v?.incident;
            minicbor::Encode::encode(&value, &mut minicbor::Encoder::new(&mut count), &mut ())?;
            values.push(value);
        }
        values.sort_by_key(|v| (v.family, v.anchor));
        ensure!(
            values
                .windows(2)
                .all(|w| (w[0].family, w[0].anchor) < (w[1].family, w[1].anchor)),
            "incident export tuple duplicate"
        );
        Ok(values)
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn access(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)> {
        self.inner.access(key)
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(
        self,
        s: std::sync::Arc<dyn crate::permanent::Storage<Value>>,
    ) -> Result<Self> {
        ensure!(
            s.currency() == self.currency && s.tag() == format!("{}/incidents", self.home),
            "incident storage context"
        );
        Ok(Self {
            inner: self.inner.on_empty_storage(s)?,
            ..self
        })
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn seal(&mut self) -> Result<()> {
        self.inner.seal()
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.inner.snapshot()
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical(&self, bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: self.inner.historical(bytes)?,
            ..self.clone()
        })
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        Ok(Self {
            inner: self.inner.empty_storage()?,
            ..self.clone()
        })
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn capture(
        self,
        budget: crate::permanent::capture::Budget,
    ) -> Result<(Self, crate::permanent::capture::Capture<Value>)> {
        let (inner, trace) =
            self.inner
                .capture(self.currency, &format!("{}/incidents", self.home), budget)?;
        Ok((Self { inner, ..self }, trace))
    }
}
impl serde::Serialize for Incidents {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        serde::Serialize::serialize(
            &self
                .canonical_records()
                .map_err(serde::ser::Error::custom)?,
            s,
        )
    }
}
impl<C> minicbor::Encode<C> for Incidents {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        let values = self.canonical_records().map_err(|_| {
            minicbor::encode::Error::message("complete incident material unavailable")
        })?;
        minicbor::Encode::encode(&values, e, c)
    }
}
