//! Insert/replace native records. No removal; complete wire records stay canonical.
//! Host storage starts at checked empty genesis and derives roots by native execution.
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
    fn replace(&self, value: T) -> Result<Arc<dyn Storage<T>>>;
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)>;
    fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_>;
    fn seal(&self) -> Result<Arc<dyn Storage<T>>>;
    fn snapshot(&self) -> Result<Vec<u8>>;
    fn historical(&self, bytes: &[u8]) -> Result<Arc<dyn Storage<T>>>;
    fn empty(&self) -> Arc<dyn Storage<T>>;
}
use crate::permanent::access;
#[cfg(not(target_os = "zkvm"))]
mod capture;
pub struct Mutable<T: Record> {
    backing: Backing<T>,
}
enum Backing<T: Record> {
    Tape(access::Tape<T>),
    Full(Table<T>),
    #[cfg(not(target_os = "zkvm"))]
    Stored(Arc<dyn Storage<T>>),
}
impl<T: Record> Clone for Mutable<T> {
    fn clone(&self) -> Self {
        Self {
            backing: match &self.backing {
                Backing::Full(t) => Backing::Full(t.clone()),
                Backing::Tape(t) => Backing::Tape(t.clone()),
                #[cfg(not(target_os = "zkvm"))]
                Backing::Stored(s) => Backing::Stored(s.clone()),
            },
        }
    }
}
impl<T: Record + 'static> std::fmt::Debug for Mutable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mutable")
            .field("count", &self.len())
            .finish()
    }
}
impl<T: Record + 'static> PartialEq for Mutable<T> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.backing, &other.backing) {
            (Backing::Full(a), Backing::Full(b)) => a == b,
            (Backing::Tape(a), Backing::Tape(b)) => a.same(b),
            (Backing::Tape(_), _) | (_, Backing::Tape(_)) => false,
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
impl<T: Record + Eq + 'static> Eq for Mutable<T> {}
impl<T: Record + 'static> Mutable<T> {
    pub fn is_complete(&self) -> bool {
        !matches!(self.backing, Backing::Tape(_))
    }
    pub(crate) fn from_access(c: Id, tag: &str, a: &access::Access<T>) -> Result<Self> {
        Ok(Self {
            backing: Backing::Tape(access::Tape::new(c, tag, a)?),
        })
    }
    pub(crate) fn finish_access(&self) -> Result<()> {
        if let Backing::Tape(t) = &self.backing {
            t.finish()?;
        }
        Ok(())
    }
    pub fn new(c: Id, tag: &str) -> Self {
        Self {
            backing: Backing::Full(Table::new(c, tag)),
        }
    }
    pub fn from_sorted(c: Id, tag: &str, values: Vec<T>) -> Result<Self> {
        ensure!(
            values.iter().all(|v| v.key(c) == Key::Id(v.entry(c).key)),
            "mutable record direct native key"
        );
        Ok(Self {
            backing: Backing::Full(Table::from_sorted(c, tag, values)?),
        })
    }
    pub fn len(&self) -> u64 {
        match &self.backing {
            Backing::Full(t) => t.len() as u64,
            Backing::Tape(t) => t.count(),
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
            Backing::Tape(t) => {
                ensure!(t.matches(c, tag), "mutable access context");
                Ok(t.root())
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                ensure!(
                    s.currency() == c && s.tag() == tag,
                    "mutable storage context"
                );
                Ok(s.root())
            }
        }
    }
    pub fn get(&self, id: Id) -> Result<Option<T>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.get(id).cloned()),
            Backing::Tape(t) => t.get(id),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.get(id),
        }
    }
    pub fn contains(&self, value: &T, c: Id) -> Result<bool> {
        Ok(self.get(value.entry(c).key)?.is_some_and(|v| v == *value))
    }
    pub fn insert(&mut self, value: T) -> Result<()> {
        match &mut self.backing {
            Backing::Tape(t) => t.insert(value),
            Backing::Full(t) => {
                ensure!(
                    value.key(t.currency()) == Key::Id(value.entry(t.currency()).key),
                    "mutable record key"
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
    pub fn replace(&mut self, value: T) -> Result<()> {
        match &mut self.backing {
            Backing::Tape(t) => t.replace(value),
            Backing::Full(t) => {
                ensure!(
                    value.key(t.currency()) == Key::Id(value.entry(t.currency()).key),
                    "mutable replacement direct key"
                );
                t.replace(value)
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                let next = s.replace(value)?;
                *s = next;
                Ok(())
            }
        }
    }
    pub fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + '_> {
        match &self.backing {
            Backing::Full(t) => Box::new(t.iter().cloned().map(Ok)),
            Backing::Tape(_) => Box::new(std::iter::once(Err(anyhow::anyhow!(
                "partial mutable map cannot export complete records"
            )))),
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
            Backing::Tape(_) => {
                anyhow::bail!("partial mutable map cannot issue arbitrary membership")
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.access(key)?.0.context("mutable key absent"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn access(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)> {
        match &self.backing {
            Backing::Full(t) => t.query(key),
            Backing::Tape(_) => anyhow::bail!("complete mutable map required"),
            Backing::Stored(s) => s.access(key),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(self, s: Arc<dyn Storage<T>>) -> Result<Self> {
        ensure!(
            self.is_complete()
                && self.is_empty()
                && s.count() == 0
                && self.commitment(s.currency(), s.tag())? == s.root()
                && s.root() == crate::merkle::root(s.currency(), s.tag(), &[])?,
            "mutable storage exact empty map"
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
            _ => anyhow::bail!("mutable storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical(&self, b: &[u8]) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Ok(Self {
                backing: Backing::Stored(s.historical(b)?),
            }),
            _ => anyhow::bail!("mutable storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Self::new(s.currency(), s.tag()).on_empty_storage(s.empty()),
            _ => anyhow::bail!("mutable storage unavailable"),
        }
    }
}
impl<T: Record + Serialize + 'static> Serialize for Mutable<T> {
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
impl<C, T: Record + Encode<C> + 'static> Encode<C> for Mutable<T> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len())?;
        for v in self.records() {
            v.map_err(|_| minicbor::encode::Error::message("mutable storage read failed"))?
                .encode(e, c)?;
        }
        Ok(())
    }
}
