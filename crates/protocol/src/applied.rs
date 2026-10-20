//! Operation deduplication with either complete records or a checked access tape.
//! Tape roots are bound by a certified native predecessor, never a host assertion.
use crate::{
    codec::Id,
    merkle::{self, Absence, Entry, Membership},
    model::Applied,
    record,
    table::Table,
};
use anyhow::{Context, Result, bail, ensure};
use minicbor::{Encode, Encoder, encode::Write};
use serde::{Serialize, Serializer};
#[cfg(target_os = "zkvm")]
use std::rc::Rc as Shared;
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc as Shared;
record!(AppliedStep{id:Id => 0,member:Option<Membership> => 1,absence:Option<Absence> => 2});
record!(AppliedAccess{format:String => 0,root:Id => 1,count:u64 => 2,steps:Vec<AppliedStep> => 3});
pub const FORMAT: &str = "RLD-NATIVE-APPLIED-ACCESS-1";
/// Host adapters are initialized only at an independently checked empty genesis.
/// The node reconstructs every later snapshot from complete verified execution;
/// no serialized storage root is a ledger adoption interface.
#[cfg(not(target_os = "zkvm"))]
pub trait Storage: std::fmt::Debug + Send + Sync {
    fn currency(&self) -> Id;
    fn tag(&self) -> &str;
    fn root(&self) -> Id;
    fn count(&self) -> u64;
    fn get(&self, id: Id) -> Result<Option<Applied>>;
    fn insert(&self, value: Applied) -> Result<Shared<dyn Storage>>;
    fn seal(&self) -> Result<Shared<dyn Storage>>;
    fn access(&self, id: Id) -> Result<AppliedStep>;
    fn records(&self) -> Box<dyn Iterator<Item = Result<Applied>> + Send + '_>;
    fn snapshot(&self) -> Result<Vec<u8>>;
    fn historical(&self, snapshot: &[u8]) -> Result<Shared<dyn Storage>>;
    fn empty(&self) -> Shared<dyn Storage>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tape {
    currency: Id,
    tag: String,
    root: Id,
    count: u64,
    steps: Shared<Vec<AppliedStep>>,
    cursor: usize,
}
#[derive(Clone, Debug)]
enum Backing {
    Full(Table<Applied>),
    Tape(Tape),
    #[cfg(not(target_os = "zkvm"))]
    Stored(Shared<dyn Storage>),
}
#[derive(Clone, Debug)]
pub struct AppliedIndex {
    backing: Backing,
}
impl PartialEq for AppliedIndex {
    fn eq(&self, other: &Self) -> bool {
        match (&self.backing, &other.backing) {
            (Backing::Full(a), Backing::Full(b)) => a == b,
            (Backing::Tape(a), Backing::Tape(b)) => a == b,
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
            _ => false,
        }
    }
}
impl Eq for AppliedIndex {}
impl AppliedIndex {
    #[cfg(not(target_os = "zkvm"))]
    pub fn on_empty_storage(self, storage: Shared<dyn Storage>) -> Result<Self> {
        ensure!(
            self.is_complete()
                && self.is_empty()
                && storage.count() == 0
                && self.commitment(storage.currency(), storage.tag())? == storage.root()
                && storage.root() == merkle::root(storage.currency(), storage.tag(), &[])?,
            "storage must begin at the exact independently checked empty map"
        );
        Ok(Self {
            backing: Backing::Stored(storage),
        })
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn seal_storage(&mut self) -> Result<()> {
        if let Backing::Stored(s) = &mut self.backing {
            let next = s.seal()?;
            *s = next;
        }
        Ok(())
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn storage_snapshot(&self) -> Result<Option<Vec<u8>>> {
        match &self.backing {
            Backing::Stored(s) => Ok(Some(s.snapshot()?)),
            _ => Ok(None),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn historical_storage(&self, bytes: &[u8]) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Ok(Self {
                backing: Backing::Stored(s.historical(bytes)?),
            }),
            _ => bail!("applied storage owner unavailable"),
        }
    }
    #[cfg(not(target_os = "zkvm"))]
    pub fn empty_storage(&self) -> Result<Self> {
        match &self.backing {
            Backing::Stored(s) => Self::new(s.currency(), s.tag()).on_empty_storage(s.empty()),
            _ => bail!("applied storage owner unavailable"),
        }
    }
    pub fn new(c: Id, tag: &str) -> Self {
        Self {
            backing: Backing::Full(Table::new(c, tag)),
        }
    }
    pub fn from_sorted(c: Id, tag: &str, values: Vec<Applied>) -> Result<Self> {
        Ok(Self {
            backing: Backing::Full(Table::from_sorted(c, tag, values)?),
        })
    }
    pub(crate) fn from_access(c: Id, tag: &str, access: &AppliedAccess) -> Result<Self> {
        ensure!(
            access.format == FORMAT && !access.steps.is_empty() && access.steps.len() <= 4096 * 64,
            "applied access format/count"
        );
        Ok(Self {
            backing: Backing::Tape(Tape {
                currency: c,
                tag: tag.into(),
                root: access.root,
                count: access.count,
                steps: Shared::new(access.steps.clone()),
                cursor: 0,
            }),
        })
    }
    pub fn is_empty(&self) -> bool {
        match &self.backing {
            Backing::Full(t) => t.is_empty(),
            Backing::Tape(t) => t.count == 0,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t.count() == 0,
        }
    }
    pub fn is_complete(&self) -> bool {
        !matches!(self.backing, Backing::Tape(_))
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        match &self.backing {
            Backing::Full(t) => t.commitment(c, tag),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => {
                ensure!(
                    t.currency() == c && t.tag() == tag,
                    "applied storage context"
                );
                Ok(t.root())
            }
            Backing::Tape(t) => {
                ensure!(t.currency == c && t.tag == tag, "applied tape context");
                Ok(t.root)
            }
        }
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.entries()),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t
                .records()
                .map(|v| {
                    let v = v?;
                    Ok(Entry {
                        key: v.id,
                        value: v.digest,
                    })
                })
                .collect(),
            _ => bail!("partial applied index cannot publish complete records"),
        }
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        match &self.backing {
            Backing::Full(t) => t.witness(key),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t.access(key)?.member.context("missing stored applied key"),
            _ => bail!("partial applied index cannot issue arbitrary membership"),
        }
    }
    pub fn get(&self, id: Id) -> Result<Option<Applied>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.get(id).cloned()),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t.get(id),
            Backing::Tape(t) => {
                let step = t.steps.get(t.cursor).context("missing applied access")?;
                ensure!(step.id == id, "applied access order/key");
                match (&step.member, &step.absence) {
                    (Some(m), None) => {
                        ensure!(
                            m.entry.key == id && m.path.count == t.count,
                            "applied member binding/count"
                        );
                        merkle::verify(t.currency, &t.tag, t.root, m)?;
                        Ok(Some(Applied {
                            id,
                            digest: m.entry.value,
                        }))
                    }
                    (None, Some(a)) => {
                        ensure!(a.count == t.count, "applied absence count");
                        merkle::verify_absent(t.currency, &t.tag, t.root, id, a)?;
                        Ok(None)
                    }
                    _ => bail!("applied access requires one proof"),
                }
            }
        }
    }
    pub fn acknowledge_existing(&mut self, id: Id) -> Result<()> {
        ensure!(self.get(id)?.is_some(), "existing applied record required");
        if let Backing::Tape(t) = &mut self.backing {
            t.cursor = t
                .cursor
                .checked_add(1)
                .context("applied access cursor overflow")?;
        }
        Ok(())
    }
    pub fn insert(&mut self, value: Applied) -> Result<()> {
        match &mut self.backing {
            Backing::Full(t) => t.insert(value),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => {
                let next = t.insert(value)?;
                *t = next;
                Ok(())
            }
            Backing::Tape(t) => {
                let step = t.steps.get(t.cursor).context("missing applied insertion")?;
                ensure!(
                    step.id == value.id && step.member.is_none(),
                    "applied insertion identity/duplicate"
                );
                let absence = step.absence.as_ref().context("applied insertion absence")?;
                ensure!(absence.count == t.count, "applied insertion count");
                let root = merkle::insert_absent(
                    t.currency,
                    &t.tag,
                    t.root,
                    &Entry {
                        key: value.id,
                        value: value.digest,
                    },
                    absence,
                )?;
                let count = t.count.checked_add(1).context("applied count overflow")?;
                let cursor = t.cursor.checked_add(1).context("applied cursor overflow")?;
                t.root = root;
                t.count = count;
                t.cursor = cursor;
                Ok(())
            }
        }
    }
    pub(crate) fn finish(&self) -> Result<()> {
        if let Backing::Tape(t) = &self.backing {
            ensure!(t.cursor == t.steps.len(), "unused applied access suffix");
        }
        Ok(())
    }
    pub fn access_step(&self, id: Id) -> Result<AppliedStep> {
        match &self.backing {
            Backing::Full(t) => {
                let (member, absence) = t.query(id)?;
                Ok(AppliedStep {
                    id,
                    member,
                    absence,
                })
            }
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t.access(id),
            _ => bail!("complete applied index required to build access"),
        }
    }
    pub fn full_access(&self, c: Id, tag: &str) -> Result<AppliedAccess> {
        ensure!(self.is_complete(), "complete applied index required");
        let count = match &self.backing {
            Backing::Full(t) => u64::try_from(t.len())?,
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => t.count(),
            _ => unreachable!(),
        };
        Ok(AppliedAccess {
            format: FORMAT.into(),
            root: self.commitment(c, tag)?,
            count,
            steps: vec![],
        })
    }
}
impl Serialize for AppliedIndex {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match &self.backing {
            Backing::Full(t) => t.serialize(s),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => {
                use serde::ser::SerializeSeq;
                let mut seq = s.serialize_seq(Some(
                    usize::try_from(t.count()).map_err(serde::ser::Error::custom)?,
                ))?;
                for value in t.records() {
                    seq.serialize_element(&value.map_err(serde::ser::Error::custom)?)?;
                }
                seq.end()
            }
            _ => Err(serde::ser::Error::custom(
                "cannot serialize partial applied state",
            )),
        }
    }
}
impl<C> Encode<C> for AppliedIndex {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        match &self.backing {
            Backing::Full(t) => t.encode(e, c),
            #[cfg(not(target_os = "zkvm"))]
            Backing::Stored(t) => {
                e.array(t.count())?;
                for value in t.records() {
                    value
                        .map_err(|_| {
                            minicbor::encode::Error::message("applied storage read failed")
                        })?
                        .encode(e, c)?;
                }
                Ok(())
            }
            _ => Err(minicbor::encode::Error::message(
                "cannot encode partial applied state",
            )),
        }
    }
}
