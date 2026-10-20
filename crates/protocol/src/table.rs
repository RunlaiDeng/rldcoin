//! Persistent ordered native tables. Tree topology/cached sizes are process
//! representation only: wire state still contains the complete sorted values.
//! Decoding reconstructs the tree; it never adopts serialized index metadata.
use crate::{
    codec::{Id, hash},
    merkle::{Entry, Map, Membership},
    model::*,
};
use anyhow::{Context, Result, ensure};
use minicbor::{Encode, Encoder, encode::Write};
use serde::{Serialize, Serializer};
#[cfg(target_os = "zkvm")]
use std::rc::Rc as Shared;
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc as Shared;
use std::{cmp::Ordering, fmt, ops::Index};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Id(Id),
    Segment(Id, u32),
    Incident(Id, Id),
}
pub trait Record: Clone + PartialEq {
    fn key(&self, currency: Id) -> Key;
    fn entry(&self, currency: Id) -> Entry;
}
macro_rules! direct {($($kind:ty => ($field:ident,$tag:literal)),* $(,)?)=>{$(impl Record for $kind{
    fn key(&self,_:Id)->Key{Key::Id(self.$field)}
    fn entry(&self,c:Id)->Entry{Entry{key:self.$field,value:hash($tag,c,self)}}
})*};}
direct!(Output=>(id,"RLD-OUTPUT"),Grant=>(id,"RLD-GRANT"),Controller=>(id,"RLD-CONTROLLER"),Birth=>(controller,"RLD-BIRTH"),Delegation=>(coupon,"RLD-DELEGATION"),Family=>(id,"RLD-FAMILY"),Decision=>(object,"RLD-DECISION"),Redemption=>(controller,"RLD-REDEMPTION"),Service=>(id,"RLD-SERVICE"),MintRecord=>(event,"RLD-MINT-RECORD"));
impl Record for Applied {
    fn key(&self, _: Id) -> Key {
        Key::Id(self.id)
    }
    fn entry(&self, _: Id) -> Entry {
        Entry {
            key: self.id,
            value: self.digest,
        }
    }
}
impl Record for Id {
    fn key(&self, _: Id) -> Key {
        Key::Id(*self)
    }
    fn entry(&self, _: Id) -> Entry {
        Entry {
            key: *self,
            value: *self,
        }
    }
}
impl Record for Segment {
    fn key(&self, _: Id) -> Key {
        Key::Segment(self.grant, self.cursor)
    }
    fn entry(&self, c: Id) -> Entry {
        Entry {
            key: hash("RLD-SEGMENT-KEY", c, &(self.grant, self.cursor)),
            value: hash("RLD-SEGMENT", c, self),
        }
    }
}
impl Record for Incident {
    fn key(&self, _: Id) -> Key {
        Key::Incident(self.family, self.anchor)
    }
    fn entry(&self, c: Id) -> Entry {
        Entry {
            key: hash("RLD-INCIDENT-KEY", c, &(self.family, self.anchor)),
            value: hash("RLD-INCIDENT", c, self),
        }
    }
}
impl Record for Cover {
    fn key(&self, c: Id) -> Key {
        Key::Id(self.id(c))
    }
    fn entry(&self, c: Id) -> Entry {
        Entry {
            key: self.id(c),
            value: hash("RLD-COVER", c, self),
        }
    }
}
impl Record for FeePolicy {
    fn key(&self, c: Id) -> Key {
        Key::Id(self.id(c))
    }
    fn entry(&self, c: Id) -> Entry {
        Entry {
            key: self.id(c),
            value: self.id(c),
        }
    }
}

type Link<T> = Option<Shared<Node<T>>>;
struct Node<T> {
    key: Key,
    value: Shared<T>,
    left: Link<T>,
    right: Link<T>,
    height: u8,
    len: usize,
}
pub struct Table<T: Record> {
    currency: Id,
    root: Link<T>,
    map: Map,
}
impl<T: Record> Clone for Table<T> {
    fn clone(&self) -> Self {
        Self {
            currency: self.currency,
            root: self.root.clone(),
            map: self.map.clone(),
        }
    }
}
impl<T: Record> PartialEq for Table<T> {
    fn eq(&self, other: &Self) -> bool {
        self.currency == other.currency
            && self.map.same_context(&other.map)
            && self.len() == other.len()
            && self.iter().eq(other.iter())
    }
}
impl<T: Record + Eq> Eq for Table<T> {}
impl<T: Record + fmt::Debug> fmt::Debug for Table<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
fn height<T>(n: &Link<T>) -> u8 {
    n.as_ref().map_or(0, |n| n.height)
}
fn size<T>(n: &Link<T>) -> usize {
    n.as_ref().map_or(0, |n| n.len)
}
fn node<T>(key: Key, value: Shared<T>, left: Link<T>, right: Link<T>) -> Result<Shared<Node<T>>> {
    let len = size(&left)
        .checked_add(size(&right))
        .and_then(|n| n.checked_add(1))
        .context("table count exhaustion")?;
    let height = height(&left)
        .max(height(&right))
        .checked_add(1)
        .context("table height exhaustion")?;
    Ok(Shared::new(Node {
        key,
        value,
        left,
        right,
        height,
        len,
    }))
}
fn balance<T>(
    key: Key,
    value: Shared<T>,
    left: Link<T>,
    right: Link<T>,
) -> Result<Shared<Node<T>>> {
    let delta = height(&left) as i16 - height(&right) as i16;
    if delta > 1 {
        let l = left.as_ref().context("table left rotation child")?;
        if height(&l.left) >= height(&l.right) {
            let r = node(key, value, l.right.clone(), right)?;
            node(l.key, l.value.clone(), l.left.clone(), Some(r))
        } else {
            let m = l.right.as_ref().context("table double rotation child")?;
            let a = node(l.key, l.value.clone(), l.left.clone(), m.left.clone())?;
            let b = node(key, value, m.right.clone(), right)?;
            node(m.key, m.value.clone(), Some(a), Some(b))
        }
    } else if delta < -1 {
        let r = right.as_ref().context("table right rotation child")?;
        if height(&r.right) >= height(&r.left) {
            let l = node(key, value, left, r.left.clone())?;
            node(r.key, r.value.clone(), Some(l), r.right.clone())
        } else {
            let m = r.left.as_ref().context("table double rotation child")?;
            let a = node(key, value, left, m.left.clone())?;
            let b = node(r.key, r.value.clone(), m.right.clone(), r.right.clone())?;
            node(m.key, m.value.clone(), Some(a), Some(b))
        }
    } else {
        node(key, value, left, right)
    }
}
fn insert<T>(root: &Link<T>, key: Key, value: Shared<T>, replace: bool) -> Result<Shared<Node<T>>> {
    let Some(n) = root else {
        ensure!(!replace, "table replacement missing");
        return node(key, value, None, None);
    };
    match key.cmp(&n.key) {
        Ordering::Less => balance(
            n.key,
            n.value.clone(),
            Some(insert(&n.left, key, value, replace)?),
            n.right.clone(),
        ),
        Ordering::Greater => balance(
            n.key,
            n.value.clone(),
            n.left.clone(),
            Some(insert(&n.right, key, value, replace)?),
        ),
        Ordering::Equal => {
            ensure!(replace, "duplicate table key");
            node(key, value, n.left.clone(), n.right.clone())
        }
    }
}
fn remove<T>(root: &Link<T>, key: Key) -> Result<Link<T>> {
    let Some(n) = root else {
        return Ok(None);
    };
    Ok(match key.cmp(&n.key) {
        Ordering::Less => Some(balance(
            n.key,
            n.value.clone(),
            remove(&n.left, key)?,
            n.right.clone(),
        )?),
        Ordering::Greater => Some(balance(
            n.key,
            n.value.clone(),
            n.left.clone(),
            remove(&n.right, key)?,
        )?),
        Ordering::Equal => match (&n.left, &n.right) {
            (None, _) => n.right.clone(),
            (_, None) => n.left.clone(),
            (Some(_), Some(r)) => {
                let mut next = r.as_ref();
                while let Some(l) = &next.left {
                    next = l.as_ref();
                }
                Some(balance(
                    next.key,
                    next.value.clone(),
                    n.left.clone(),
                    remove(&n.right, next.key)?,
                )?)
            }
        },
    })
}
impl<T: Record> Table<T> {
    pub fn new(currency: Id, tag: &str) -> Self {
        Self {
            currency,
            root: None,
            map: Map::new(currency, tag),
        }
    }
    pub(crate) fn currency(&self) -> Id {
        self.currency
    }
    pub fn commitment(&self, currency: Id, tag: &str) -> Result<Id> {
        ensure!(
            self.map.matches(currency, tag) && self.map.count() == u64::try_from(self.len())?,
            "native table commitment context/count"
        );
        Ok(self.map.root())
    }
    pub fn entries(&self) -> Vec<Entry> {
        let mut entries: Vec<_> = self.iter().map(|v| v.entry(self.currency)).collect();
        entries.sort_by_key(|e| e.key);
        entries
    }
    pub fn query(&self, key: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)> {
        self.map.query(key)
    }
    pub fn witness(&self, key: Id) -> Result<Membership> {
        self.map.prove_key(key)
    }
    pub fn len(&self) -> usize {
        size(&self.root)
    }
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
    pub fn get_key(&self, key: Key) -> Option<&T> {
        let mut current = self.root.as_deref();
        while let Some(n) = current {
            match key.cmp(&n.key) {
                Ordering::Less => current = n.left.as_deref(),
                Ordering::Greater => current = n.right.as_deref(),
                Ordering::Equal => return Some(n.value.as_ref()),
            }
        }
        None
    }
    pub fn get(&self, key: Id) -> Option<&T> {
        self.get_key(Key::Id(key))
    }
    pub fn before_or_at(&self, key: Key) -> Option<&T> {
        let mut current = self.root.as_deref();
        let mut found = None;
        while let Some(n) = current {
            if key < n.key {
                current = n.left.as_deref();
            } else {
                found = Some(n.value.as_ref());
                current = n.right.as_deref();
            }
        }
        found
    }
    pub fn contains(&self, value: &T) -> bool {
        self.get_key(value.key(self.currency))
            .is_some_and(|v| v == value)
    }
    pub fn insert(&mut self, value: T) -> Result<()> {
        let mut map = self.map.clone();
        map.insert(value.entry(self.currency))?;
        let root = insert(
            &self.root,
            value.key(self.currency),
            Shared::new(value),
            false,
        )?;
        self.root = Some(root);
        self.map = map;
        Ok(())
    }
    pub fn replace(&mut self, value: T) -> Result<()> {
        let old = self
            .get_key(value.key(self.currency))
            .context("table replacement missing")?;
        ensure!(
            old.entry(self.currency).key == value.entry(self.currency).key,
            "replacement changes native key"
        );
        let mut map = self.map.clone();
        map.replace(value.entry(self.currency))?;
        let root = insert(
            &self.root,
            value.key(self.currency),
            Shared::new(value),
            true,
        )?;
        self.root = Some(root);
        self.map = map;
        Ok(())
    }
    pub fn remove_key(&mut self, key: Key) -> Result<Option<T>> {
        let value = self.get_key(key).cloned();
        if let Some(v) = &value {
            let mut map = self.map.clone();
            map.remove(v.entry(self.currency).key)?;
            let root = remove(&self.root, key)?;
            self.root = root;
            self.map = map;
        }
        Ok(value)
    }
    pub fn remove(&mut self, key: Id) -> Result<Option<T>> {
        self.remove_key(Key::Id(key))
    }
    pub fn at(&self, mut index: usize) -> Option<&T> {
        let mut current = self.root.as_deref();
        while let Some(n) = current {
            let left = size(&n.left);
            if index < left {
                current = n.left.as_deref();
            } else if index == left {
                return Some(n.value.as_ref());
            } else {
                index -= left + 1;
                current = n.right.as_deref();
            }
        }
        None
    }
    pub fn iter(&self) -> Iter<'_, T> {
        let mut iter = Iter {
            stack: vec![],
            remaining: self.len(),
        };
        iter.descend(self.root.as_deref());
        iter
    }
    pub fn from_sorted(currency: Id, tag: &str, values: Vec<T>) -> Result<Self> {
        ensure!(
            values
                .windows(2)
                .all(|w| w[0].key(currency) < w[1].key(currency)),
            "noncanonical table order/duplicate"
        );
        let mut entries: Vec<_> = values.iter().map(|v| v.entry(currency)).collect();
        entries.sort_by_key(|e| e.key);
        let map = Map::from_entries(currency, tag, &entries)?;
        let count = values.len();
        let mut values = values.into_iter();
        fn build<T: Record>(
            c: Id,
            values: &mut impl Iterator<Item = T>,
            n: usize,
        ) -> Result<Link<T>> {
            if n == 0 {
                return Ok(None);
            }
            let left = build(c, values, n / 2)?;
            let value = values.next().context("complete table records")?;
            let key = value.key(c);
            let right = build(c, values, n - n / 2 - 1)?;
            Ok(Some(node(key, Shared::new(value), left, right)?))
        }
        Ok(Self {
            currency,
            root: build(currency, &mut values, count)?,
            map,
        })
    }
}
impl<T: Record> Index<usize> for Table<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        self.at(index).expect("retained table ordinal")
    }
}
pub struct Iter<'a, T> {
    stack: Vec<&'a Node<T>>,
    remaining: usize,
}
impl<'a, T> Iter<'a, T> {
    fn descend(&mut self, mut n: Option<&'a Node<T>>) {
        while let Some(value) = n {
            self.stack.push(value);
            n = value.left.as_deref();
        }
    }
}
impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        let n = self.stack.pop()?;
        self.descend(n.right.as_deref());
        self.remaining -= 1;
        Some(n.value.as_ref())
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl<T> ExactSizeIterator for Iter<'_, T> {}
impl<'a, T: Record> IntoIterator for &'a Table<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<T: Record + Serialize> Serialize for Table<T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_seq(self.iter())
    }
}
impl<C, T: Record + Encode<C>> Encode<C> for Table<T> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        c: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len() as u64)?;
        for value in self.iter() {
            value.encode(e, c)?;
        }
        Ok(())
    }
}
