//! Immutable native UTXO paths with reachable-only in-memory working nodes.
//! Published objects are never pruned; only uncommitted Arc versions can drop.
use crate::{
    object_store::{Object, Objects},
    runtime::Initial,
};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, encode},
    merkle::{self, Absence, Entry, Membership},
    model::Output,
    record,
    table::Record,
    utxo::Storage,
};
use std::{path::Path, sync::Arc};
const FORMAT: &str = "RLD-UTXO-DISK-1";
const PAGE: usize = 512;
const VALUE: usize = 8192;
const WORK_OBJECTS: u64 = 600_000;
const WORK_BYTES: u64 = 512 * 1024 * 1024;
record!(Link{object:Object => 0,native:Id => 1,count:u64 => 2,first:Id => 3,last:Id => 4,height:u8 => 5,depth:u16 => 6});
record!(Node{format:String => 0,currency:Id => 1,home:Id => 2,entry:Option<Entry> => 3,value:Option<Object> => 4,left:Option<Link> => 5,right:Option<Link> => 6});
record!(Snapshot{format:String => 0,currency:Id => 1,home:Id => 2,genesis:Id => 3,root:Option<Link> => 4});
#[derive(Clone)]
struct Tree {
    link: Link,
    work: Option<Arc<Work>>,
}
struct Work {
    bytes: Arc<Vec<u8>>,
    value: Option<Arc<Vec<u8>>>,
    left: Option<Tree>,
    right: Option<Tree>,
    objects: u64,
    bytes_count: u64,
}
struct Owner {
    objects: Arc<Objects>,
    currency: Id,
    home: Id,
    genesis: Id,
    tag: String,
}
#[derive(Clone)]
pub(crate) struct Utxos {
    owner: Arc<Owner>,
    root: Option<Tree>,
}
impl std::fmt::Debug for Utxos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Utxos")
            .field("count", &self.count())
            .field("root", &self.root())
            .finish()
    }
}
struct Read {
    node: Node,
    left: Option<Tree>,
    right: Option<Tree>,
    value: Option<Arc<Vec<u8>>>,
}
fn frozen(link: Link) -> Tree {
    Tree { link, work: None }
}
fn usage(tree: &Option<Tree>) -> (u64, u64) {
    tree.as_ref()
        .and_then(|t| t.work.as_ref())
        .map_or((0, 0), |w| (w.objects, w.bytes_count))
}
impl Utxos {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let currency = initial.currency.id();
        let home = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        Ok(Self {
            owner: Arc::new(Owner {
                objects: Objects::open(path, &encode(&(FORMAT, currency, home, genesis)))?,
                currency,
                home,
                genesis,
                tag: format!("{home}/outputs"),
            }),
            root: None,
        })
    }
    pub(crate) fn status(&self) -> Result<crate::object_store::ObjectStatus> {
        self.owner.objects.status()
    }
    fn summary(&self, object: Object, n: &Node) -> Result<Link> {
        ensure!(
            n.format == FORMAT && n.currency == self.owner.currency && n.home == self.owner.home,
            "UTXO node context"
        );
        match (&n.entry, &n.value, &n.left, &n.right) {
            (Some(e), Some(v), None, None) => {
                ensure!(v.bytes > 0 && v.bytes <= VALUE as u64, "UTXO value size");
                Ok(Link {
                    object,
                    native: merkle::leaf_hash(self.currency(), &self.owner.tag, e),
                    count: 1,
                    first: e.key,
                    last: e.key,
                    height: 0,
                    depth: 256,
                })
            }
            (None, None, Some(l), Some(r)) => {
                ensure!(
                    l.count > 0
                        && r.count > 0
                        && l.first <= l.last
                        && r.first <= r.last
                        && l.last < r.first,
                    "UTXO child order/count"
                );
                let d = merkle::branch_depth(l.first, r.last)?;
                ensure!(
                    l.depth <= 256
                        && r.depth <= 256
                        && l.depth > d as u16
                        && r.depth > d as u16
                        && !merkle::bit(l.first, d)
                        && !merkle::bit(l.last, d)
                        && merkle::bit(r.first, d)
                        && merkle::bit(r.last, d)
                        && merkle::prefix(l.first, d) == merkle::prefix(r.last, d),
                    "UTXO child prefix/depth"
                );
                let height = l
                    .height
                    .max(r.height)
                    .checked_add(1)
                    .context("UTXO height exhaustion")?;
                ensure!(height as usize <= merkle::MAX_PATH, "UTXO path bound");
                Ok(Link {
                    object,
                    native: merkle::branch_hash(
                        self.currency(),
                        &self.owner.tag,
                        d,
                        l.first,
                        l.native,
                        l.count,
                        r.native,
                        r.count,
                    ),
                    count: l
                        .count
                        .checked_add(r.count)
                        .context("UTXO count exhaustion")?,
                    first: l.first,
                    last: r.last,
                    height,
                    depth: d as u16,
                })
            }
            _ => anyhow::bail!("incomplete UTXO node"),
        }
    }
    fn read(&self, t: &Tree) -> Result<Read> {
        let bytes = if let Some(w) = &t.work {
            ensure!(
                w.bytes.len() as u64 == t.link.object.bytes
                    && Id::digest(w.bytes.as_slice()) == t.link.object.digest,
                "UTXO working object identity"
            );
            w.bytes.clone()
        } else {
            self.owner.objects.read(&t.link.object, PAGE)?
        };
        let n: Node = decode(bytes.as_slice(), PAGE)?;
        ensure!(
            self.summary(t.link.object.clone(), &n)? == t.link,
            "UTXO retained summary"
        );
        let (left, right, value) = if let Some(w) = &t.work {
            ensure!(
                w.left.as_ref().map(|t| t.link.clone()) == n.left
                    && w.right.as_ref().map(|t| t.link.clone()) == n.right,
                "UTXO working children"
            );
            (w.left.clone(), w.right.clone(), w.value.clone())
        } else {
            (
                n.left.clone().map(frozen),
                n.right.clone().map(frozen),
                None,
            )
        };
        Ok(Read {
            node: n,
            left,
            right,
            value,
        })
    }
    fn make(
        &self,
        entry: Option<Entry>,
        value: Option<Arc<Vec<u8>>>,
        left: Option<Tree>,
        right: Option<Tree>,
    ) -> Result<Tree> {
        let object_value = value.as_ref().map(|b| Object {
            digest: Id::digest(b.as_slice()),
            bytes: b.len() as u64,
        });
        let node = Node {
            format: FORMAT.into(),
            currency: self.currency(),
            home: self.home(),
            entry,
            value: object_value,
            left: left.as_ref().map(|t| t.link.clone()),
            right: right.as_ref().map(|t| t.link.clone()),
        };
        let bytes = Arc::new(encode(&node));
        ensure!(bytes.len() <= PAGE, "UTXO fixed page bound");
        let link = self.summary(
            Object {
                digest: Id::digest(bytes.as_slice()),
                bytes: bytes.len() as u64,
            },
            &node,
        )?;
        let (lc, lb) = usage(&left);
        let (rc, rb) = usage(&right);
        let objects = lc
            .checked_add(rc)
            .and_then(|n| n.checked_add(1 + u64::from(value.is_some())))
            .context("UTXO working object overflow")?;
        let bytes_count = lb
            .checked_add(rb)
            .and_then(|n| n.checked_add(bytes.len() as u64))
            .and_then(|n| n.checked_add(value.as_ref().map_or(0, |v| v.len() as u64)))
            .context("UTXO working byte overflow")?;
        ensure!(
            objects <= WORK_OBJECTS && bytes_count <= WORK_BYTES,
            "UTXO working capacity exhausted; no publication"
        );
        Ok(Tree {
            link,
            work: Some(Arc::new(Work {
                bytes,
                value,
                left,
                right,
                objects,
                bytes_count,
            })),
        })
    }
    fn leaf(&self, value: Output) -> Result<Tree> {
        rld_protocol::utxo::Outputs::validate(&value, self.home())?;
        let e = value.entry(self.currency());
        let bytes = Arc::new(rld_protocol::codec::encode_bounded(&value, VALUE)?);
        self.make(Some(e), Some(bytes), None, None)
    }
    fn branch(&self, l: Tree, r: Tree) -> Result<Tree> {
        self.make(None, None, Some(l), Some(r))
    }
    fn insert_at(&self, root: &Option<Tree>, value: Output) -> Result<Tree> {
        let Some(t) = root else {
            return self.leaf(value);
        };
        let key = value.id;
        if key != t.link.first && u16::from(merkle::branch_depth(t.link.first, key)?) < t.link.depth
        {
            let n = self.leaf(value)?;
            return if key < t.link.first {
                self.branch(n, t.clone())
            } else {
                self.branch(t.clone(), n)
            };
        }
        let read = self.read(t)?;
        ensure!(read.node.entry.is_none(), "duplicate UTXO key");
        let l = read.left.context("UTXO left")?;
        let r = read.right.context("UTXO right")?;
        if merkle::bit(key, u8::try_from(t.link.depth)?) {
            self.branch(l, self.insert_at(&Some(r), value)?)
        } else {
            self.branch(self.insert_at(&Some(l), value)?, r)
        }
    }
    fn remove_at(&self, t: &Tree, key: Id) -> Result<Option<Tree>> {
        let read = self.read(t)?;
        if let Some(e) = read.node.entry {
            ensure!(e.key == key, "UTXO removal key");
            return Ok(None);
        }
        let l = read.left.context("UTXO remove left")?;
        let r = read.right.context("UTXO remove right")?;
        if merkle::bit(key, u8::try_from(t.link.depth)?) {
            match self.remove_at(&r, key)? {
                Some(n) => Ok(Some(self.branch(l, n)?)),
                None => Ok(Some(l)),
            }
        } else {
            match self.remove_at(&l, key)? {
                Some(n) => Ok(Some(self.branch(n, r)?)),
                None => Ok(Some(r)),
            }
        }
    }
    fn value(&self, read: Read) -> Result<Output> {
        let object = read.node.value.context("UTXO leaf value")?;
        let bytes = if let Some(b) = read.value {
            b
        } else {
            self.owner.objects.read(&object, VALUE)?
        };
        ensure!(
            bytes.len() as u64 == object.bytes && Id::digest(bytes.as_slice()) == object.digest,
            "UTXO value identity"
        );
        let value: Output = decode(bytes.as_slice(), VALUE)?;
        rld_protocol::utxo::Outputs::validate(&value, self.home())?;
        ensure!(
            Some(value.entry(self.currency())) == read.node.entry,
            "UTXO native value commitment"
        );
        Ok(value)
    }
    fn rank(&self, key: Id) -> Result<(u64, bool)> {
        let mut current = self.root.clone();
        let mut rank = 0u64;
        for _ in 0..=64 {
            let Some(t) = current else {
                return Ok((rank, false));
            };
            let read = self.read(&t)?;
            if key < t.link.first {
                return Ok((rank, false));
            }
            if key > t.link.last {
                return Ok((
                    rank.checked_add(t.link.count)
                        .context("UTXO rank overflow")?,
                    false,
                ));
            }
            if let Some(e) = read.node.entry {
                return Ok((rank, e.key == key));
            }
            let l = read.left.context("UTXO rank left")?;
            let r = read.right.context("UTXO rank right")?;
            current = if merkle::bit(key, u8::try_from(t.link.depth)?) {
                rank = rank
                    .checked_add(l.link.count)
                    .context("UTXO rank overflow")?;
                Some(r)
            } else {
                Some(l)
            };
        }
        anyhow::bail!("UTXO rank depth")
    }
    fn at(&self, index: u64) -> Result<(Membership, Output)> {
        ensure!(index < self.count(), "UTXO ordinal");
        let mut t = self.root.clone().context("UTXO root")?;
        let mut rank = index;
        let mut path = merkle::Path {
            index,
            count: self.count(),
            siblings: vec![],
            depths: vec![],
            counts: vec![],
        };
        loop {
            let read = self.read(&t)?;
            if let Some(e) = &read.node.entry {
                ensure!(rank == 0, "UTXO leaf rank");
                let member = Membership {
                    entry: e.clone(),
                    path,
                };
                merkle::verify(self.currency(), &self.owner.tag, self.root(), &member)?;
                return Ok((member, self.value(read)?));
            }
            ensure!(path.depths.len() < 64, "UTXO path depth");
            let l = read.left.context("UTXO proof left")?;
            let r = read.right.context("UTXO proof right")?;
            path.depths.push(u8::try_from(t.link.depth)?);
            if rank < l.link.count {
                path.siblings.push(r.link.native);
                path.counts.push(r.link.count);
                t = l
            } else {
                rank -= l.link.count;
                path.siblings.push(l.link.native);
                path.counts.push(l.link.count);
                t = r
            }
        }
    }
}
impl Storage for Utxos {
    fn currency(&self) -> Id {
        self.owner.currency
    }
    fn home(&self) -> Id {
        self.owner.home
    }
    fn count(&self) -> u64 {
        self.root.as_ref().map_or(0, |t| t.link.count)
    }
    fn root(&self) -> Id {
        merkle::root_hash(
            self.currency(),
            &self.owner.tag,
            self.count(),
            self.root.as_ref().map_or_else(
                || merkle::empty_hash(self.currency(), &self.owner.tag),
                |t| t.link.native,
            ),
        )
    }
    fn get(&self, key: Id) -> Result<Option<Output>> {
        let (rank, found) = self.rank(key)?;
        if found {
            let (m, v) = self.at(rank)?;
            ensure!(m.entry.key == key, "UTXO lookup key");
            Ok(Some(v))
        } else {
            self.access(key)?;
            Ok(None)
        }
    }
    fn insert(&self, value: Output) -> Result<Arc<dyn Storage>> {
        let root = self.insert_at(&self.root, value)?;
        ensure!(
            self.count().checked_add(1) == Some(root.link.count),
            "UTXO insertion cardinality"
        );
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: Some(root),
        }))
    }
    fn spend(&self, key: Id) -> Result<(Arc<dyn Storage>, Option<Output>)> {
        let Some(value) = self.get(key)? else {
            return Ok((Arc::new(self.clone()), None));
        };
        let member = self.access(key)?.0.context("UTXO spend member")?;
        let expected =
            merkle::remove_member(self.currency(), &self.owner.tag, self.root(), &member)?;
        let root = self.remove_at(self.root.as_ref().context("UTXO spend root")?, key)?;
        let next = Self {
            owner: self.owner.clone(),
            root,
        };
        ensure!(
            next.root() == expected && self.count().checked_sub(1) == Some(next.count()),
            "UTXO complete/compact removal root"
        );
        Ok((Arc::new(next), Some(value)))
    }
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        let (rank, found) = self.rank(key)?;
        if found {
            return Ok((Some(self.at(rank)?.0), None));
        }
        let a = Absence {
            count: self.count(),
            left: if rank > 0 {
                Some(self.at(rank - 1)?.0)
            } else {
                None
            },
            right: if rank < self.count() {
                Some(self.at(rank)?.0)
            } else {
                None
            },
        };
        merkle::verify_absent(self.currency(), &self.owner.tag, self.root(), key, &a)?;
        Ok((None, Some(a)))
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<Output>> + Send + '_> {
        Box::new(Records {
            store: self.clone(),
            stack: self.root.clone().into_iter().collect(),
            remaining: self.count(),
            failed: false,
        })
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
        let mut stack: Vec<_> = self.root.clone().into_iter().collect();
        while let Some(t) = stack.pop() {
            let Some(w) = &t.work else { continue };
            let read = self.read(&t)?;
            if let Some(value) = &w.value {
                let object = read.node.value.context("UTXO seal value")?;
                ensure!(
                    self.owner.objects.put(value.as_ref().clone(), VALUE)? == object,
                    "UTXO sealed value identity"
                );
            }
            ensure!(
                self.owner.objects.put(w.bytes.as_ref().clone(), PAGE)? == t.link.object,
                "UTXO sealed page identity"
            );
            if let Some(l) = &w.left {
                stack.push(l.clone())
            }
            if let Some(r) = &w.right {
                stack.push(r.clone())
            }
        }
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: self.root.as_ref().map(|t| frozen(t.link.clone())),
        }))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        ensure!(usage(&self.root) == (0, 0), "unsealed UTXO observation");
        Ok(encode(&Snapshot {
            format: FORMAT.into(),
            currency: self.currency(),
            home: self.home(),
            genesis: self.owner.genesis,
            root: self.root.as_ref().map(|t| t.link.clone()),
        }))
    }
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage>> {
        let s: Snapshot = decode(b, 4096)?;
        ensure!(
            s.format == FORMAT
                && s.currency == self.currency()
                && s.home == self.home()
                && s.genesis == self.owner.genesis,
            "UTXO observation context"
        );
        let next = Self {
            owner: self.owner.clone(),
            root: s.root.map(frozen),
        };
        if let Some(t) = &next.root {
            next.read(t)?;
        }
        Ok(Arc::new(next))
    }
    fn empty(&self) -> Arc<dyn Storage> {
        Arc::new(Self {
            owner: self.owner.clone(),
            root: None,
        })
    }
}
struct Records {
    store: Utxos,
    stack: Vec<Tree>,
    remaining: u64,
    failed: bool,
}
impl Iterator for Records {
    type Item = Result<Output>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            let Some(t) = self.stack.pop() else {
                if self.remaining != 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("UTXO stream incomplete")));
                }
                return None;
            };
            let read = match self.store.read(&t) {
                Ok(v) => v,
                Err(e) => {
                    self.failed = true;
                    return Some(Err(e));
                }
            };
            if read.node.entry.is_some() {
                if self.remaining == 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("UTXO stream overflow")));
                }
                self.remaining -= 1;
                let v = self.store.value(read);
                if v.is_err() {
                    self.failed = true
                }
                return Some(v);
            }
            if let (Some(l), Some(r)) = (read.left, read.right) {
                self.stack.push(r);
                self.stack.push(l)
            } else {
                self.failed = true;
                return Some(Err(anyhow::anyhow!("UTXO stream branch")));
            }
        }
    }
}
