//! Process-local persistent index over completely authenticated native records.
//! This is neither a serialized authorization cache nor a new ledger commitment.
//! Cold startup reconstructs it by full ordinary journal/native verification.
use crate::runtime::Committed;
use anyhow::{Context, Result, ensure};
use std::{slice, sync::Arc};

const BITS: u32 = 5;
const WIDTH: usize = 1 << BITS;
#[derive(Clone)]
enum Tree {
    Leaf(Vec<Arc<Committed>>),
    Branch(Vec<Arc<Tree>>),
}
#[derive(Clone, Default)]
pub struct History {
    root: Option<Arc<Tree>>,
    height: u32,
    len: usize,
}
impl History {
    pub fn push(&mut self, value: Committed) -> Result<()> {
        let next = self
            .len
            .checked_add(1)
            .context("native history count exhaustion")?;
        ensure!(
            u64::try_from(next)? == value.header.sequence,
            "native history must append the next exact sequence"
        );
        let value = Arc::new(value);
        if let Some(root) = &mut self.root {
            let shift = (self.height + 1) * BITS;
            if shift < usize::BITS && self.len >> shift != 0 {
                self.root = Some(Arc::new(Tree::Branch(vec![root.clone()])));
                self.height += 1;
            }
            append(
                self.root.as_mut().context("history root")?,
                self.height,
                self.len,
                value,
            )?;
        } else {
            ensure!(self.len == 0 && self.height == 0, "empty history identity");
            self.root = Some(Arc::new(Tree::Leaf(vec![value])));
        }
        self.len = next;
        Ok(())
    }
    pub fn at(&self, sequence: u64) -> Option<&Committed> {
        let index = usize::try_from(sequence.checked_sub(1)?).ok()?;
        if index >= self.len {
            return None;
        }
        let mut tree = self.root.as_deref()?;
        let mut height = self.height;
        loop {
            match tree {
                Tree::Leaf(values) => return values.get(index & (WIDTH - 1)).map(Arc::as_ref),
                Tree::Branch(children) => {
                    tree = children
                        .get((index >> (height * BITS)) & (WIDTH - 1))?
                        .as_ref();
                    height = height.checked_sub(1)?;
                }
            }
        }
    }
    pub fn iter(&self) -> Iter<'_> {
        self.after(0)
    }
    /// Iterate only records strictly after this sequence, seeking directly to
    /// the first leaf without traversing all earlier records.
    pub fn after(&self, sequence: u64) -> Iter<'_> {
        let index = usize::try_from(sequence).unwrap_or(usize::MAX);
        let mut iter = Iter {
            pending: vec![],
            leaf: None,
            remaining: self.len.saturating_sub(index),
        };
        if index >= self.len {
            return iter;
        }
        let Some(mut tree) = self.root.as_deref() else {
            return iter;
        };
        let mut height = self.height;
        loop {
            match tree {
                Tree::Leaf(values) => {
                    iter.leaf = Some(values[index & (WIDTH - 1)..].iter());
                    return iter;
                }
                Tree::Branch(children) => {
                    let offset = (index >> (height * BITS)) & (WIDTH - 1);
                    iter.pending
                        .extend(children[offset + 1..].iter().rev().map(Arc::as_ref));
                    tree = children[offset].as_ref();
                    height -= 1;
                }
            }
        }
    }
}
fn path(height: u32, value: Arc<Committed>) -> Arc<Tree> {
    Arc::new(if height == 0 {
        Tree::Leaf(vec![value])
    } else {
        Tree::Branch(vec![path(height - 1, value)])
    })
}
fn append(tree: &mut Arc<Tree>, height: u32, index: usize, value: Arc<Committed>) -> Result<()> {
    match Arc::make_mut(tree) {
        Tree::Leaf(values) => {
            ensure!(
                height == 0 && values.len() < WIDTH && values.len() == (index & (WIDTH - 1)),
                "native history leaf position"
            );
            values.push(value);
        }
        Tree::Branch(children) => {
            ensure!(height > 0, "native history branch depth");
            let offset = (index >> (height * BITS)) & (WIDTH - 1);
            if offset == children.len() {
                ensure!(children.len() < WIDTH, "native history branch capacity");
                children.push(path(height - 1, value));
            } else {
                append(
                    children
                        .get_mut(offset)
                        .context("native history branch gap")?,
                    height - 1,
                    index,
                    value,
                )?;
            }
        }
    }
    Ok(())
}
pub struct Iter<'a> {
    pending: Vec<&'a Tree>,
    leaf: Option<slice::Iter<'a, Arc<Committed>>>,
    remaining: usize,
}
impl<'a> Iterator for Iter<'a> {
    type Item = &'a Committed;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(value) = self.leaf.as_mut().and_then(Iterator::next) {
                self.remaining -= 1;
                return Some(value.as_ref());
            }
            match self.pending.pop()? {
                Tree::Leaf(values) => self.leaf = Some(values.iter()),
                Tree::Branch(children) => {
                    self.pending.extend(children.iter().rev().map(Arc::as_ref))
                }
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}
impl ExactSizeIterator for Iter<'_> {}
