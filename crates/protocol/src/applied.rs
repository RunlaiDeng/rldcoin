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
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tape {
    currency: Id,
    tag: String,
    root: Id,
    count: u64,
    steps: Shared<Vec<AppliedStep>>,
    cursor: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Backing {
    Full(Table<Applied>),
    Tape(Tape),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedIndex {
    backing: Backing,
}
impl AppliedIndex {
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
        }
    }
    pub fn is_complete(&self) -> bool {
        matches!(self.backing, Backing::Full(_))
    }
    pub fn commitment(&self, c: Id, tag: &str) -> Result<Id> {
        match &self.backing {
            Backing::Full(t) => t.commitment(c, tag),
            Backing::Tape(t) => {
                ensure!(t.currency == c && t.tag == tag, "applied tape context");
                Ok(t.root)
            }
        }
    }
    pub fn entries(&self) -> Result<Vec<Entry>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.entries()),
            _ => bail!("partial applied index cannot publish complete records"),
        }
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        match &self.backing {
            Backing::Full(t) => t.witness(key),
            _ => bail!("partial applied index cannot issue arbitrary membership"),
        }
    }
    pub fn get(&self, id: Id) -> Result<Option<Applied>> {
        match &self.backing {
            Backing::Full(t) => Ok(t.get(id).cloned()),
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
            _ => bail!("complete applied index required to build access"),
        }
    }
    pub fn full_access(&self, c: Id, tag: &str) -> Result<AppliedAccess> {
        ensure!(self.is_complete(), "complete applied index required");
        let count = match &self.backing {
            Backing::Full(t) => u64::try_from(t.len())?,
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
            _ => Err(minicbor::encode::Error::message(
                "cannot encode partial applied state",
            )),
        }
    }
}
