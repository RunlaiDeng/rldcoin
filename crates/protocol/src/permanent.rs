//! Append-only native records. Complete wire records remain canonical; host
//! storage starts at checked empty genesis and derives roots by native execution.
use crate::{
    codec::Id,
    merkle::{Entry, Membership},
    table::{Key, Record, Table},
};
use anyhow::{Context, Result, ensure};
use minicbor::{Encode, Encoder, encode::Write};
use serde::{Serialize, Serializer};
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc;
#[cfg(not(target_os = "zkvm"))]
pub trait Storage<T: Record>: std::fmt::Debug + Send + Sync {
    fn currency(&self) -> Id;
    fn tag(&self) -> &str;
    fn root(&self) -> Id;
    fn count(&self) -> u64;
    fn get(&self, id: Id) -> Result<Option<T>>;
    fn insert(&self, value: T) -> Result<Arc<dyn Storage<T>>>;
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)>;
    fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_>;
    fn seal(&self) -> Result<Arc<dyn Storage<T>>>;
    fn snapshot(&self) -> Result<Vec<u8>>;
    fn historical(&self, bytes: &[u8]) -> Result<Arc<dyn Storage<T>>>;
    fn empty(&self) -> Arc<dyn Storage<T>>;
}
pub struct Permanent<T: Record> {
    backing: Backing<T>,
}
enum Backing<T: Record> {
    Full(Table<T>),
    #[cfg(not(target_os = "zkvm"))]
    Stored(Arc<dyn Storage<T>>),
}
impl<T: Record> Clone for Permanent<T> {
    fn clone(&self) -> Self {
        Self {
            backing: match &self.backing {
                Backing::Full(t) => Backing::Full(t.clone()),
                #[cfg(not(target_os = "zkvm"))]
                Backing::Stored(s) => Backing::Stored(s.clone()),
            },
        }
    }
}
impl<T: Record + 'static> std::fmt::Debug for Permanent<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permanent")
            .field("count", &self.len())
            .finish()
    }
}
impl<T: Record> PartialEq for Permanent<T> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.backing, &other.backing) {
            (Backing::Full(a), Backing::Full(b)) => a == b,
            #[cfg(not(target_os = "zkvm"))]
            (Backing::Stored(a), Backing::Stored(b)) => {
                a.currency() == b.currency()
                    && a.tag() == b.tag()
                    && a.root() == b.root()
                    && a.count() == b.count()
            }
            #[cfg(not(target_os = "zkvm"))]
            (Backing::Stored(a), Backing::Full(b)) | (Backing::Full(b), Backing::Stored(a)) => {
                u64::try_from(b.len()).ok() == Some(a.count())
                    && b.commitment(a.currency(), a.tag()).ok() == Some(a.root())
            }
        }
    }
}
impl<T: Record + Eq> Eq for Permanent<T> {}
impl<T: Record + 'static> Permanent<T> {
    pub fn new(c: Id, tag: &str) -> Self {
        Self {
            backing: Backing::Full(Table::new(c, tag)),
        }
    }
    pub fn from_sorted(c: Id, tag: &str, values: Vec<T>) -> Result<Self> {
        ensure!(
            values.iter().all(|v| v.key(c) == Key::Id(v.entry(c).key)),
            "permanent record direct native key"
        );
        Ok(Self {
            backing: Backing::Full(Table::from_sorted(c, tag, values)?),
        })
    }
    pub fn len(&self) -> u64 {
        match &self.backing {
            Backing::Full(t) => t.len() as u64,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.count(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        match &self.backing {
            Backing::Full(t) => t.commitment(c, tag),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                ensure!(
                    s.currency() == c && s.tag() == tag,
                    "permanent storage context"
                );
                Ok(s.root())
            }
        }
    }
    pub fn get(&self, id: Id) -> Result<Option<T>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.get(id).cloned()),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.get(id),
        }
    }
    pub fn contains(&self, value: &T, c: Id) -> Result<bool> {
        Ok(self.get(value.entry(c).key)?.is_some_and(|v| v == *value))
    }
    pub fn insert(&mut self, value: T) -> Result<()> {
        match &mut self.backing {
            Backing::Full(t) => {
                ensure!(
                    value.key(t.currency()) == Key::Id(value.entry(t.currency()).key),
                    "permanent record key"
                );
                t.insert(value)
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                let next = s.insert(value)?;
                *s = next;
                Ok(())
            }
        }
    }
    pub fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + '_> {
        match &self.backing {
            Backing::Full(t) => Box::new(t.iter().cloned().map(Ok)),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.records(),
        }
    }
    pub fn entries(&self, c: Id) -> Result<Vec<Entry>> {
        self.records().map(|v| Ok(v?.entry(c))).collect()
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        match &self.backing {
            Backing::Full(t) => t.witness(key),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.access(key)?.0.context("permanent key absent"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn access(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)> {
        match &self.backing {
            Backing::Full(t) => t.query(key),
            Backing::Stored(s) => s.access(key),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(self, s: Arc<dyn Storage<T>>) -> Result<Self> {
        ensure!(
            self.is_empty()
                && s.count() == 0
                && self.commitment(s.currency(), s.tag())? == s.root()
                && s.root() == crate::merkle::root(s.currency(), s.tag(), &[])?,
            "permanent storage exact empty map"
        );
        Ok(Self {
            backing: Backing::Stored(s),
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
            _ => anyhow::bail!("permanent storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical(&self, b: &[u8]) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Ok(Self {
                backing: Backing::Stored(s.historical(b)?),
            }),
            _ => anyhow::bail!("permanent storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Self::new(s.currency(), s.tag()).on_empty_storage(s.empty()),
            _ => anyhow::bail!("permanent storage unavailable"),
        }
    }
}
impl<T: Record + Serialize + 'static> Serialize for Permanent<T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut out = s.serialize_seq(Some(
            usize::try_from(self.len()).map_err(serde::ser::Error::custom)?,
        ))?;
        for value in self.records() {
            out.serialize_element(&value.map_err(serde::ser::Error::custom)?)?;
        }
        out.end()
    }
}
impl<C, T: Record + Encode<C> + 'static> Encode<C> for Permanent<T> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len())?;
        for v in self.records() {
            v.map_err(|_| minicbor::encode::Error::message("permanent storage read failed"))?
                .encode(e, c)?;
        }
        Ok(())
    }
}
