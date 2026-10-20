use super::*;
use crate::merkle::{self, Absence};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "zkvm")]
use std::{cell::RefCell as Usage, rc::Rc as Shared};
#[cfg(not(target_os = "zkvm"))]
use std::{sync::Arc as Shared, sync::Mutex as Usage};
pub const FORMAT: &str = "RLD-NATIVE-PERMANENT-ACCESS-1";
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
#[serde(deny_unknown_fields)]
#[cbor(array)]
pub struct AccessStep<T> {
    #[n(0)]
    pub root: Id,
    #[n(1)]
    pub count: u64,
    #[n(2)]
    pub key: Id,
    #[n(3)]
    pub value: Option<T>,
    #[n(4)]
    pub member: Option<Membership>,
    #[n(5)]
    pub absence: Option<Absence>,
}
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    minicbor::Encode,
    minicbor::Decode,
)]
#[serde(deny_unknown_fields)]
#[cbor(array)]
pub struct Access<T> {
    #[n(0)]
    pub format: String,
    #[n(1)]
    pub root: Id,
    #[n(2)]
    pub count: u64,
    #[n(3)]
    pub steps: Vec<AccessStep<T>>,
    #[n(4)]
    pub opening: Option<Membership>,
}
struct Set<T> {
    steps: Vec<AccessStep<T>>,
    index: BTreeMap<(Id, Id), usize>,
    used: Usage<BTreeSet<usize>>,
}
#[derive(Clone)]
pub(crate) struct Tape<T> {
    currency: Id,
    tag: String,
    root: Id,
    count: u64,
    set: Shared<Set<T>>,
}
impl<T: Record + 'static> Tape<T> {
    pub(crate) fn new(c: Id, tag: &str, a: &Access<T>) -> Result<Self> {
        ensure!(
            a.format == FORMAT && a.steps.len() <= 2_000_000,
            "permanent access format/count"
        );
        if a.count == 0 {
            ensure!(
                a.opening.is_none() && a.root == merkle::root(c, tag, &[])?,
                "permanent empty root/count opening"
            );
        } else {
            let opening = a
                .opening
                .as_ref()
                .context("permanent root/count opening missing")?;
            ensure!(
                opening.path.count == a.count,
                "permanent root opening count"
            );
            merkle::verify(c, tag, a.root, opening)?;
        }
        let mut index = BTreeMap::new();
        for (i, s) in a.steps.iter().enumerate() {
            ensure!(
                index.insert((s.root, s.key), i).is_none(),
                "duplicate permanent access root/key"
            );
        }
        Ok(Self {
            currency: c,
            tag: tag.into(),
            root: a.root,
            count: a.count,
            set: Shared::new(Set {
                steps: a.steps.clone(),
                index,
                used: Usage::new(BTreeSet::new()),
            }),
        })
    }
    pub(crate) fn root(&self) -> Id {
        self.root
    }
    pub(crate) fn count(&self) -> u64 {
        self.count
    }
    pub(crate) fn matches(&self, c: Id, tag: &str) -> bool {
        self.currency == c && self.tag == tag
    }
    pub(crate) fn same(&self, o: &Self) -> bool {
        self.currency == o.currency
            && self.tag == o.tag
            && self.root == o.root
            && self.count == o.count
            && self.set.steps == o.set.steps
    }
    fn step(&self, key: Id) -> Result<(usize, &AccessStep<T>)> {
        let i = *self
            .set
            .index
            .get(&(self.root, key))
            .context("missing permanent access root/key")?;
        let s = &self.set.steps[i];
        ensure!(s.count == self.count, "permanent access current count");
        Ok((i, s))
    }
    pub(crate) fn get(&self, key: Id) -> Result<Option<T>> {
        let (i, s) = self.step(key)?;
        match (&s.value, &s.member, &s.absence) {
            (Some(v), Some(m), None) => {
                ensure!(
                    v.key(self.currency) == Key::Id(key)
                        && v.entry(self.currency) == m.entry
                        && m.entry.key == key
                        && m.path.count == self.count,
                    "permanent typed member binding"
                );
                merkle::verify(self.currency, &self.tag, self.root, m)?;
            }
            (None, None, Some(a)) => {
                ensure!(a.count == self.count, "permanent absence count");
                merkle::verify_absent(self.currency, &self.tag, self.root, key, a)?;
            }
            _ => anyhow::bail!("permanent access requires exact typed member or absence"),
        }
        #[cfg(not(target_os = "zkvm"))]
        self.set
            .used
            .lock()
            .map_err(|_| anyhow::anyhow!("permanent access observation unavailable"))?
            .insert(i);
        #[cfg(target_os = "zkvm")]
        self.set
            .used
            .try_borrow_mut()
            .map_err(|_| anyhow::anyhow!("permanent access observation unavailable"))?
            .insert(i);
        Ok(s.value.clone())
    }
    pub(crate) fn insert(&mut self, value: T) -> Result<()> {
        let e = value.entry(self.currency);
        ensure!(
            value.key(self.currency) == Key::Id(e.key),
            "permanent direct insert key"
        );
        ensure!(
            self.get(e.key)?.is_none(),
            "duplicate permanent tape insertion"
        );
        let (_, s) = self.step(e.key)?;
        let root = merkle::insert_absent(
            self.currency,
            &self.tag,
            self.root,
            &e,
            s.absence.as_ref().context("permanent insert absence")?,
        )?;
        let count = self
            .count
            .checked_add(1)
            .context("permanent tape count exhaustion")?;
        self.root = root;
        self.count = count;
        Ok(())
    }
    pub(crate) fn finish(&self) -> Result<()> {
        #[cfg(not(target_os = "zkvm"))]
        let used = self
            .set
            .used
            .lock()
            .map_err(|_| anyhow::anyhow!("permanent access observation unavailable"))?
            .len();
        #[cfg(target_os = "zkvm")]
        let used = self
            .set
            .used
            .try_borrow()
            .map_err(|_| anyhow::anyhow!("permanent access observation unavailable"))?
            .len();
        ensure!(
            used == self.set.steps.len(),
            "unused permanent access evidence"
        );
        Ok(())
    }
}

impl Tape<crate::model::Output> {
    pub(crate) fn remove_output(&mut self, key: Id) -> Result<Option<crate::model::Output>> {
        let Some(value) = self.get(key)? else {
            return Ok(None);
        };
        let (_, s) = self.step(key)?;
        let root = crate::merkle::remove_member(
            self.currency,
            &self.tag,
            self.root,
            s.member.as_ref().context("UTXO removal member")?,
        )?;
        let count = self.count.checked_sub(1).context("UTXO removal count")?;
        self.root = root;
        self.count = count;
        Ok(Some(value))
    }
}
