//! Validated spendable outputs. Only this map can remove proven records; the
//! permanent decision maps retain their append-only public interface.
use crate::{
    codec::{Amount, Id},
    merkle::{Absence, Entry, Membership},
    model::Output,
    permanent::access::{Access, Tape},
    table::Table,
};
use anyhow::{Context, Result, ensure};
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc;
#[cfg(not(target_os = "zkvm"))]
pub trait Storage: std::fmt::Debug + Send + Sync {
    fn currency(&self) -> Id;
    fn home(&self) -> Id;
    fn root(&self) -> Id;
    fn count(&self) -> u64;
    fn get(&self, key: Id) -> Result<Option<Output>>;
    fn insert(&self, value: Output) -> Result<Arc<dyn Storage>>;
    fn spend(&self, key: Id) -> Result<(Arc<dyn Storage>, Option<Output>)>;
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)>;
    fn records(&self) -> Box<dyn Iterator<Item = Result<Output>> + Send + '_>;
    fn seal(&self) -> Result<Arc<dyn Storage>>;
    fn snapshot(&self) -> Result<Vec<u8>>;
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage>>;
    fn empty(&self) -> Arc<dyn Storage>;
}
#[derive(Clone)]
enum Backing {
    Full(Table<Output>),
    Tape(Tape<Output>),
    #[cfg(not(target_os = "zkvm"))]
    Stored(Arc<dyn Storage>),
}
#[derive(Clone)]
pub struct Outputs {
    currency: Id,
    home: Id,
    backing: Backing,
}
impl std::fmt::Debug for Outputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outputs")
            .field("count", &self.len())
            .finish()
    }
}
impl PartialEq for Outputs {
    fn eq(&self, o: &Self) -> bool {
        self.currency == o.currency
            && self.home == o.home
            && match (&self.backing, &o.backing) {
                (Backing::Full(a), Backing::Full(b)) => a == b,
                (Backing::Tape(a), Backing::Tape(b)) => a.same(b),
                #[cfg(not(target_os = "zkvm"))]
                (Backing::Stored(a), Backing::Stored(b)) => {
                    a.root() == b.root() && a.count() == b.count()
                }
                #[cfg(not(target_os = "zkvm"))]
                (Backing::Stored(a), Backing::Full(b)) | (Backing::Full(b), Backing::Stored(a)) => {
                    b.len() as u64 == a.count()
                        && b.commitment(self.currency, &self.tag()).ok() == Some(a.root())
                }
                _ => false,
            }
    }
}
impl Eq for Outputs {}
impl Outputs {
    fn tag(&self) -> String {
        format!("{}/outputs", self.home)
    }
    pub fn new(c: Id, home: Id) -> Self {
        Self {
            currency: c,
            home,
            backing: Backing::Full(Table::new(c, &format!("{home}/outputs"))),
        }
    }
    pub fn validate(value: &Output, home: Id) -> Result<()> {
        ensure!(value.home == home, "foreign UTXO");
        value.owner.validate()?;
        ensure!(
            !value.components.is_empty()
                && value.components.len() <= 64
                && value.components.windows(2).all(|w| w[0].cover < w[1].cover)
                && value.components.iter().all(|v| v.amount.0 > 0),
            "output component order/count/zero"
        );
        value
            .components
            .iter()
            .try_fold(Amount(0), |n, v| n.add(v.amount))?;
        Ok(())
    }
    pub fn from_sorted(c: Id, home: Id, values: Vec<Output>) -> Result<Self> {
        for v in &values {
            Self::validate(v, home)?;
        }
        Ok(Self {
            currency: c,
            home,
            backing: Backing::Full(Table::from_sorted(c, &format!("{home}/outputs"), values)?),
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
    pub fn is_complete(&self) -> bool {
        !matches!(self.backing, Backing::Tape(_))
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        ensure!(
            c == self.currency && tag == self.tag(),
            "UTXO commitment context"
        );
        match &self.backing {
            Backing::Full(t) => t.commitment(c, tag),
            Backing::Tape(t) => {
                ensure!(t.matches(c, tag), "UTXO tape context");
                Ok(t.root())
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => Ok(s.root()),
        }
    }
    pub fn get(&self, key: Id) -> Result<Option<Output>> {
        let v = match &self.backing {
            Backing::Full(t) => t.get(key).cloned(),
            Backing::Tape(t) => t.get(key)?,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.get(key)?,
        };
        if let Some(v) = &v {
            Self::validate(v, self.home)?;
        }
        Ok(v)
    }
    pub fn insert(&mut self, value: Output) -> Result<()> {
        Self::validate(&value, self.home)?;
        match &mut self.backing {
            Backing::Full(t) => t.insert(value),
            Backing::Tape(t) => t.insert(value),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                let n = s.insert(value)?;
                *s = n;
                Ok(())
            }
        }
    }
    pub fn remove(&mut self, key: Id) -> Result<Option<Output>> {
        let expected = self.get(key)?;
        if expected.is_none() {
            return Ok(None);
        }
        let removed = match &mut self.backing {
            Backing::Full(t) => t.remove(key)?,
            Backing::Tape(t) => t.remove_output(key)?,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => {
                let (n, v) = s.spend(key)?;
                *s = n;
                v
            }
        };
        ensure!(removed == expected, "UTXO spend changed checked record");
        Ok(removed)
    }
    pub fn records(&self) -> Box<dyn Iterator<Item = Result<Output>> + '_> {
        let it: Box<dyn Iterator<Item = Result<Output>> + '_> = match &self.backing {
            Backing::Full(t) => Box::new(t.iter().cloned().map(Ok)),
            Backing::Tape(_) => Box::new(std::iter::once(Err(anyhow::anyhow!(
                "partial UTXO cannot export complete records"
            )))),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.records(),
        };
        Box::new(it.map(move |v| {
            let v = v?;
            Self::validate(&v, self.home)?;
            Ok(v)
        }))
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        use crate::table::Record;
        self.records()
            .map(|v| Ok(v?.entry(self.currency)))
            .collect()
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        match &self.backing {
            Backing::Full(t) => t.witness(key),
            Backing::Tape(_) => anyhow::bail!("partial UTXO cannot issue arbitrary membership"),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(s) => s.access(key)?.0.context("UTXO absent"),
        }
    }
    pub(crate) fn from_access(c: Id, home: Id, a: &Access<Output>) -> Result<Self> {
        Ok(Self {
            currency: c,
            home,
            backing: Backing::Tape(Tape::new(c, &format!("{home}/outputs"), a)?),
        })
    }
    pub(crate) fn finish_access(&self) -> Result<()> {
        if let Backing::Tape(t) = &self.backing {
            t.finish()?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        match &self.backing {
            Backing::Full(t) => t.query(key),
            Backing::Tape(_) => anyhow::bail!("complete UTXO required"),
            Backing::Stored(s) => s.access(key),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(self, s: Arc<dyn Storage>) -> Result<Self> {
        ensure!(
            self.is_complete()
                && self.is_empty()
                && s.count() == 0
                && s.currency() == self.currency
                && s.home() == self.home
                && self.commitment(self.currency, &self.tag())? == s.root(),
            "UTXO exact checked empty storage"
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
            _ => anyhow::bail!("UTXO storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical(&self, b: &[u8]) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Ok(Self {
                backing: Backing::Stored(s.historical(b)?),
                ..self.clone()
            }),
            _ => anyhow::bail!("UTXO storage unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Self::new(self.currency, self.home).on_empty_storage(s.empty()),
            _ => anyhow::bail!("UTXO storage unavailable"),
        }
    }
}
impl serde::Serialize for Outputs {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut out = s.serialize_seq(Some(
            usize::try_from(self.len()).map_err(serde::ser::Error::custom)?,
        ))?;
        for v in self.records() {
            out.serialize_element(&v.map_err(serde::ser::Error::custom)?)?;
        }
        out.end()
    }
}
impl<C> minicbor::Encode<C> for Outputs {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len())?;
        for v in self.records() {
            v.map_err(|_| minicbor::encode::Error::message("UTXO storage read failed"))?
                .encode(e, c)?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "zkvm"))]
mod capture;
