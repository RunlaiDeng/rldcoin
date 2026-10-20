//! Counted compressed binary-prefix commitments. Private node caches are rebuilt
//! from complete records, never deserialized as native authority.
use crate::{
    codec::{Id, hash},
    record,
};
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "zkvm")]
use std::rc::Rc as Shared;
#[cfg(not(target_os = "zkvm"))]
use std::sync::Arc as Shared;

pub const MAX_PATH: usize = 64;
record!(Entry {key:Id => 0,value:Id => 1});
record!(Path {index:u64 => 0,count:u64 => 1,siblings:Vec<Id> => 2,depths:Vec<u8> => 3,counts:Vec<u64> => 4});
record!(Membership {entry:Entry => 0,path:Path => 1});
record!(Absence {left:Option<Membership> => 0,right:Option<Membership> => 1,count:u64 => 2});

pub fn bit(key: Id, depth: u8) -> bool {
    key.0[depth as usize / 8] & (0x80 >> (depth % 8)) != 0
}
pub fn prefix(key: Id, depth: u8) -> Id {
    let mut b = key.0;
    let byte = depth as usize / 8;
    let rest = depth % 8;
    if rest == 0 {
        b[byte..].fill(0);
    } else {
        b[byte] &= 0xff << (8 - rest);
        b[byte + 1..].fill(0);
    }
    Id(b)
}
pub fn branch_depth(first: Id, last: Id) -> Result<u8> {
    for (i, (a, b)) in first.0.iter().zip(last.0).enumerate() {
        let difference = *a ^ b;
        if difference != 0 {
            return Ok((i as u32 * 8 + difference.leading_zeros()) as u8);
        }
    }
    anyhow::bail!("prefix branch requires distinct keys")
}
pub fn leaf_hash(c: Id, tag: &str, e: &Entry) -> Id {
    hash("RLD-MAP-LEAF", c, &(tag, e))
}
pub fn empty_hash(c: Id, tag: &str) -> Id {
    hash("RLD-MAP-PREFIX-EMPTY-1", c, &tag)
}
pub fn branch_hash(
    c: Id,
    tag: &str,
    depth: u8,
    key: Id,
    left: Id,
    left_count: u64,
    right: Id,
    right_count: u64,
) -> Id {
    hash(
        "RLD-MAP-PREFIX-NODE-1",
        c,
        &(
            tag,
            depth,
            prefix(key, depth),
            left,
            left_count,
            right,
            right_count,
        ),
    )
}
pub fn root_hash(c: Id, tag: &str, count: u64, tree: Id) -> Id {
    hash("RLD-MAP-PREFIX-ROOT-1", c, &(tag, count, tree))
}
struct ContextKey {
    currency: Id,
    tag: String,
}
enum Body {
    Leaf(Entry),
    Branch {
        depth: u8,
        left: Shared<Node>,
        right: Shared<Node>,
    },
}
struct Node {
    hash: Id,
    count: u64,
    first: Id,
    last: Id,
    height: u8,
    body: Body,
}
#[derive(Clone)]
pub struct Map {
    context: Shared<ContextKey>,
    root: Option<Shared<Node>>,
}
fn depth(n: &Node) -> u16 {
    match n.body {
        Body::Leaf(_) => 256,
        Body::Branch { depth, .. } => depth as u16,
    }
}
fn leaf(c: &ContextKey, entry: Entry) -> Shared<Node> {
    Shared::new(Node {
        hash: leaf_hash(c.currency, &c.tag, &entry),
        count: 1,
        first: entry.key,
        last: entry.key,
        height: 0,
        body: Body::Leaf(entry),
    })
}
fn branch(c: &ContextKey, left: Shared<Node>, right: Shared<Node>) -> Result<Shared<Node>> {
    ensure!(left.last < right.first, "prefix child order/overlap");
    let split = branch_depth(left.first, right.last)?;
    ensure!(
        depth(&left) > split as u16
            && depth(&right) > split as u16
            && !bit(left.first, split)
            && !bit(left.last, split)
            && bit(right.first, split)
            && bit(right.last, split)
            && prefix(left.first, split) == prefix(right.last, split),
        "prefix child domain"
    );
    let count = left
        .count
        .checked_add(right.count)
        .context("map count exhaustion")?;
    let height = left
        .height
        .max(right.height)
        .checked_add(1)
        .context("map path exhaustion")?;
    ensure!(
        height as usize <= MAX_PATH,
        "map mutation exceeds finite membership path capacity"
    );
    Ok(Shared::new(Node {
        hash: branch_hash(
            c.currency,
            &c.tag,
            split,
            left.first,
            left.hash,
            left.count,
            right.hash,
            right.count,
        ),
        count,
        first: left.first,
        last: right.last,
        height,
        body: Body::Branch {
            depth: split,
            left,
            right,
        },
    }))
}
fn modify(
    c: &ContextKey,
    root: &Option<Shared<Node>>,
    entry: Entry,
    replace: bool,
) -> Result<Shared<Node>> {
    let Some(n) = root else {
        ensure!(!replace, "map replacement missing");
        return Ok(leaf(c, entry));
    };
    if n.first != entry.key && u16::from(branch_depth(n.first, entry.key)?) < depth(n) {
        ensure!(!replace, "map replacement missing");
        let fresh = leaf(c, entry);
        return if fresh.first < n.first {
            branch(c, fresh, n.clone())
        } else {
            branch(c, n.clone(), fresh)
        };
    }
    match &n.body {
        Body::Leaf(old) => {
            ensure!(
                old.key == entry.key && replace,
                "duplicate or missing map key"
            );
            Ok(leaf(c, entry))
        }
        Body::Branch { depth, left, right } => {
            if bit(entry.key, *depth) {
                branch(
                    c,
                    left.clone(),
                    modify(c, &Some(right.clone()), entry, replace)?,
                )
            } else {
                branch(
                    c,
                    modify(c, &Some(left.clone()), entry, replace)?,
                    right.clone(),
                )
            }
        }
    }
}
fn remove_node(
    c: &ContextKey,
    root: &Option<Shared<Node>>,
    key: Id,
) -> Result<Option<Shared<Node>>> {
    let Some(n) = root else {
        return Ok(None);
    };
    if key < n.first || key > n.last {
        return Ok(root.clone());
    }
    match &n.body {
        Body::Leaf(e) => Ok(if e.key == key { None } else { root.clone() }),
        Body::Branch { depth, left, right } => {
            if bit(key, *depth) {
                match remove_node(c, &Some(right.clone()), key)? {
                    Some(r) => Ok(Some(branch(c, left.clone(), r)?)),
                    None => Ok(Some(left.clone())),
                }
            } else {
                match remove_node(c, &Some(left.clone()), key)? {
                    Some(l) => Ok(Some(branch(c, l, right.clone())?)),
                    None => Ok(Some(right.clone())),
                }
            }
        }
    }
}
impl Map {
    pub fn new(currency: Id, tag: &str) -> Self {
        Self {
            context: Shared::new(ContextKey {
                currency,
                tag: tag.into(),
            }),
            root: None,
        }
    }
    pub fn same_context(&self, other: &Self) -> bool {
        self.matches(other.context.currency, &other.context.tag)
    }
    pub fn matches(&self, currency: Id, tag: &str) -> bool {
        self.context.currency == currency && self.context.tag == tag
    }
    pub fn count(&self) -> u64 {
        self.root.as_ref().map_or(0, |n| n.count)
    }
    pub fn tree_hash(&self) -> Id {
        self.root.as_ref().map_or_else(
            || empty_hash(self.context.currency, &self.context.tag),
            |n| n.hash,
        )
    }
    pub fn root(&self) -> Id {
        root_hash(
            self.context.currency,
            &self.context.tag,
            self.count(),
            self.tree_hash(),
        )
    }
    pub fn insert(&mut self, entry: Entry) -> Result<()> {
        let root = modify(&self.context, &self.root, entry, false)?;
        self.root = Some(root);
        Ok(())
    }
    pub fn replace(&mut self, entry: Entry) -> Result<()> {
        let root = modify(&self.context, &self.root, entry, true)?;
        self.root = Some(root);
        Ok(())
    }
    pub fn remove(&mut self, key: Id) -> Result<()> {
        self.root = remove_node(&self.context, &self.root, key)?;
        Ok(())
    }
    pub fn from_entries(currency: Id, tag: &str, entries: &[Entry]) -> Result<Self> {
        ensure!(
            entries.windows(2).all(|w| w[0].key < w[1].key),
            "map order/duplicate"
        );
        let mut map = Self::new(currency, tag);
        fn build(c: &ContextKey, e: &[Entry]) -> Result<Option<Shared<Node>>> {
            match e.len() {
                0 => Ok(None),
                1 => Ok(Some(leaf(c, e[0].clone()))),
                _ => {
                    let d = branch_depth(e[0].key, e[e.len() - 1].key)?;
                    let m = e.partition_point(|e| !bit(e.key, d));
                    ensure!(m > 0 && m < e.len(), "map prefix partition");
                    Ok(Some(branch(
                        c,
                        build(c, &e[..m])?.context("left map child")?,
                        build(c, &e[m..])?.context("right map child")?,
                    )?))
                }
            }
        }
        map.root = build(&map.context, entries)?;
        Ok(map)
    }
    pub fn query(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        let mut rank = 0u64;
        let mut current = self.root.as_deref();
        let mut found = false;
        while let Some(n) = current {
            if key < n.first {
                break;
            }
            if key > n.last {
                rank = rank
                    .checked_add(n.count)
                    .context("map query rank overflow")?;
                break;
            }
            match &n.body {
                Body::Leaf(e) => {
                    found = e.key == key;
                    break;
                }
                Body::Branch { depth, left, right } => {
                    if bit(key, *depth) {
                        rank = rank
                            .checked_add(left.count)
                            .context("map query rank overflow")?;
                        current = Some(right);
                    } else {
                        current = Some(left);
                    }
                }
            }
        }
        if found {
            return Ok((Some(self.prove(rank)?), None));
        }
        Ok((
            None,
            Some(Absence {
                count: self.count(),
                left: if rank > 0 {
                    Some(self.prove(rank - 1)?)
                } else {
                    None
                },
                right: if rank < self.count() {
                    Some(self.prove(rank)?)
                } else {
                    None
                },
            }),
        ))
    }
    pub fn prove_key(&self, key: Id) -> Result<Membership> {
        let mut rank = 0u64;
        let mut n = self.root.as_deref().context("missing map key")?;
        loop {
            match &n.body {
                Body::Leaf(e) => {
                    ensure!(e.key == key, "missing map key");
                    return self.prove(rank);
                }
                Body::Branch { depth, left, right } => {
                    if bit(key, *depth) {
                        rank = rank.checked_add(left.count).context("map rank overflow")?;
                        n = right;
                    } else {
                        n = left;
                    }
                }
            }
        }
    }
    pub fn prove(&self, index: u64) -> Result<Membership> {
        ensure!(index < self.count(), "map index");
        let mut offset = index;
        let mut n = self.root.as_deref().context("nonempty map")?;
        let mut path = Path {
            index,
            count: self.count(),
            siblings: vec![],
            depths: vec![],
            counts: vec![],
        };
        loop {
            match &n.body {
                Body::Leaf(entry) => {
                    ensure!(offset == 0, "map rank leaf");
                    return Ok(Membership {
                        entry: entry.clone(),
                        path,
                    });
                }
                Body::Branch { depth, left, right } => {
                    path.depths.push(*depth);
                    if offset < left.count {
                        path.siblings.push(right.hash);
                        path.counts.push(right.count);
                        n = left.as_ref();
                    } else {
                        offset -= left.count;
                        path.siblings.push(left.hash);
                        path.counts.push(left.count);
                        n = right.as_ref();
                    }
                }
            }
        }
    }
}
pub fn root(c: Id, tag: &str, entries: &[Entry]) -> Result<Id> {
    Ok(Map::from_entries(c, tag, entries)?.root())
}
pub fn prove(c: Id, tag: &str, entries: &[Entry], index: usize) -> Result<Membership> {
    Map::from_entries(c, tag, entries)?.prove(u64::try_from(index)?)
}
pub fn verify(c: Id, tag: &str, expected: Id, proof: &Membership) -> Result<()> {
    let p = &proof.path;
    ensure!(
        p.count > 0
            && p.index < p.count
            && p.siblings.len() <= MAX_PATH
            && p.depths.len() == p.siblings.len()
            && p.counts.len() == p.siblings.len()
            && p.depths.windows(2).all(|w| w[0] < w[1])
            && p.counts.iter().all(|n| *n > 0),
        "map path bounds/order"
    );
    let mut tree = leaf_hash(c, tag, &proof.entry);
    let mut count = 1u64;
    let mut rank = 0u64;
    for ((sibling, depth), side_count) in p.siblings.iter().zip(&p.depths).zip(&p.counts).rev() {
        tree = if bit(proof.entry.key, *depth) {
            rank = rank.checked_add(*side_count).context("map rank overflow")?;
            branch_hash(
                c,
                tag,
                *depth,
                proof.entry.key,
                *sibling,
                *side_count,
                tree,
                count,
            )
        } else {
            branch_hash(
                c,
                tag,
                *depth,
                proof.entry.key,
                tree,
                count,
                *sibling,
                *side_count,
            )
        };
        count = count
            .checked_add(*side_count)
            .context("map proof count overflow")?;
    }
    ensure!(
        count == p.count && rank == p.index && root_hash(c, tag, count, tree) == expected,
        "map proof mismatch"
    );
    Ok(())
}
pub fn verify_absent(c: Id, tag: &str, expected: Id, key: Id, p: &Absence) -> Result<()> {
    if p.count == 0 {
        ensure!(
            p.left.is_none() && p.right.is_none() && root(c, tag, &[])? == expected,
            "empty absence"
        );
        return Ok(());
    }
    for m in [&p.left, &p.right].into_iter().flatten() {
        ensure!(m.path.count == p.count, "absence count");
        verify(c, tag, expected, m)?;
    }
    match (&p.left, &p.right) {
        (Some(l), Some(r)) => ensure!(
            l.entry.key < key
                && key < r.entry.key
                && l.path.index.checked_add(1) == Some(r.path.index),
            "absence neighbors"
        ),
        (None, Some(r)) => ensure!(r.path.index == 0 && key < r.entry.key, "absence first"),
        (Some(l), None) => ensure!(
            l.path.index.checked_add(1) == Some(p.count) && l.entry.key < key,
            "absence last"
        ),
        _ => anyhow::bail!("missing absence witnesses"),
    }
    Ok(())
}

mod insertion;
pub use insertion::{CompleteSubtreeRequired, insert_absent};
