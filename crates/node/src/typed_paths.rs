//! Immutable typed native paths with reachable-only in-memory working nodes.
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
};
use std::{path::Path, sync::Arc};
pub(crate) trait Value:
    Record + minicbor::Encode<()> + for<'b> minicbor::Decode<'b, ()> + Send + Sync + 'static
{
    const FORMAT: &'static str;
    const NAME: &'static str;
    const MAX_BYTES: usize = 8192;
    fn validate(&self, home: Id) -> Result<()>;
}
impl Value for Output {
    const FORMAT: &'static str = "RLD-UTXO-DISK-1";
    const NAME: &'static str = "outputs";
    fn validate(&self, home: Id) -> Result<()> {
        rld_protocol::utxo::Outputs::validate(self, home)
    }
}
impl Value for rld_protocol::model::MintRecord {
    const FORMAT: &'static str = "RLD-MINT-EVENT-PATH-1";
    const NAME: &'static str = "mints";
    fn validate(&self, _: Id) -> Result<()> {
        rld_protocol::mints::Mints::validate(self)
    }
}
impl Value for rld_protocol::mints::Slot {
    const FORMAT: &'static str = "RLD-MINT-SLOT-PATH-1";
    const NAME: &'static str = "mint-slots-aux";
    fn validate(&self, _: Id) -> Result<()> {
        ensure!(
            self.root < rld_protocol::ROOTS && self.slot < rld_protocol::SLOTS,
            "Mint auxiliary slot range"
        );
        Ok(())
    }
}

impl Value for rld_protocol::model::Cover {
    const FORMAT: &'static str = "RLD-COVER-PATH-1";
    const NAME: &'static str = "covers";
    // A cover is not an 8-KiB coin. Keep the existing complete-state input cap;
    // reachable working bytes, disk/cache admission and outer framing still bind.
    const MAX_BYTES: usize = crate::store::MAX_RECORD;
    fn validate(&self, _: Id) -> Result<()> {
        self.validate()
    }
}
impl Value for rld_protocol::model::FeePolicy {
    const FORMAT: &'static str = "RLD-FEE-POLICY-PATH-1";
    const NAME: &'static str = "fee_policies";
    fn validate(&self, _: Id) -> Result<()> {
        self.validate()
    }
}

impl Value for rld_protocol::model::Service {
    const FORMAT: &'static str = "RLD-SERVICE-PATH-1";
    const NAME: &'static str = "services";
    fn validate(&self, _: Id) -> Result<()> {
        self.owner.validate()?;
        self.renewal_payer.validate()?;
        self.custodians.validate()?;
        ensure!(
            self.balance.len() <= 64
                && self.balance.windows(2).all(|w| w[0].cover < w[1].cover)
                && self.balance.iter().all(|p| p.amount.0 > 0),
            "stored service balance"
        );
        rld_protocol::state::sum(&self.balance)?;
        Ok(())
    }
}
impl Value for rld_protocol::model::Delegation {
    const FORMAT: &'static str = "RLD-COUPON-USE-PATH-1";
    const NAME: &'static str = "coupon_uses";
    fn validate(&self, _: Id) -> Result<()> {
        Ok(())
    }
}
impl Value for rld_protocol::model::Family {
    const FORMAT: &'static str = "RLD-FAMILY-PATH-1";
    const NAME: &'static str = "families";
    fn validate(&self, home: Id) -> Result<()> {
        self.issuer.validate()?;
        ensure!(
            self.destination == home
                && self.count > 0
                && self.count <= 4096
                && self.units >= u64::from(self.count),
            "stored receiving family"
        );
        Ok(())
    }
}
impl Value for rld_protocol::model::Controller {
    const FORMAT: &'static str = "RLD-CONTROLLER-PATH-1";
    const NAME: &'static str = "controllers";
    const MAX_BYTES: usize = crate::store::MAX_RECORD;
    fn validate(&self, home: Id) -> Result<()> {
        ensure!(self.source == home, "stored controller home");
        rld_protocol::proof::validate_controller(self)
    }
}
impl Value for rld_protocol::incidents::Value {
    const FORMAT: &'static str = "RLD-INCIDENT-PATH-1";
    const NAME: &'static str = "incidents";
    const MAX_BYTES: usize = crate::store::MAX_RECORD;
    fn validate(&self, _: Id) -> Result<()> {
        ensure!(
            !self.incident.first.0.is_empty() && !self.incident.second.0.is_empty(),
            "empty retained conflict proof"
        );
        Ok(())
    }
}

const PAGE: usize = 512;
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
pub(crate) struct Paths<T: Value> {
    owner: Arc<Owner>,
    root: Option<Tree>,
    marker: std::marker::PhantomData<fn() -> T>,
}
impl<T: Value> std::fmt::Debug for Paths<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Paths")
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
impl<T: Value> Paths<T> {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let c = initial.currency.id();
        let d = initial.genesis.configuration.domain;
        let g = rld_protocol::state::genesis_id(c, &initial.genesis);
        let objects = Objects::open(path, &encode(&(T::FORMAT, c, d, g)))?;
        Self::on_objects(objects, initial)
    }
    pub(crate) fn on_objects(objects: Arc<Objects>, initial: &Initial) -> Result<Self> {
        let currency = initial.currency.id();
        let home = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        Ok(Self {
            owner: Arc::new(Owner {
                objects,
                currency,
                home,
                genesis,
                tag: format!("{home}/{}", T::NAME),
            }),
            root: None,
            marker: std::marker::PhantomData,
        })
    }
    pub(crate) fn native_tag(&self) -> &str {
        &self.owner.tag
    }
    pub(crate) fn at_or_before(&self, key: Id) -> Result<Option<T>> {
        let (rank, found) = self.rank(key)?;
        let index = if found {
            Some(rank)
        } else {
            rank.checked_sub(1)
        };
        index.map(|i| Ok(self.at(i)?.1)).transpose()
    }
    pub(crate) fn status(&self) -> Result<crate::object_store::ObjectStatus> {
        self.owner.objects.status()
    }
    fn summary(&self, object: Object, n: &Node) -> Result<Link> {
        ensure!(
            n.format == T::FORMAT && n.currency == self.owner.currency && n.home == self.owner.home,
            "typed path node context"
        );
        match (&n.entry, &n.value, &n.left, &n.right) {
            (Some(e), Some(v), None, None) => {
                ensure!(
                    v.bytes > 0 && v.bytes <= T::MAX_BYTES as u64,
                    "typed path value size"
                );
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
                    "typed path child order/count"
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
                    "typed path child prefix/depth"
                );
                let height = l
                    .height
                    .max(r.height)
                    .checked_add(1)
                    .context("typed path height exhaustion")?;
                ensure!(height as usize <= merkle::MAX_PATH, "typed path path bound");
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
                        .context("typed path count exhaustion")?,
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
                "typed path working object identity"
            );
            w.bytes.clone()
        } else {
            self.owner.objects.read(&t.link.object, PAGE)?
        };
        let n: Node = decode(bytes.as_slice(), PAGE)?;
        ensure!(
            self.summary(t.link.object.clone(), &n)? == t.link,
            "typed path retained summary"
        );
        let (left, right, value) = if let Some(w) = &t.work {
            ensure!(
                w.left.as_ref().map(|t| t.link.clone()) == n.left
                    && w.right.as_ref().map(|t| t.link.clone()) == n.right,
                "typed path working children"
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
            format: T::FORMAT.into(),
            currency: self.currency(),
            home: self.home(),
            entry,
            value: object_value,
            left: left.as_ref().map(|t| t.link.clone()),
            right: right.as_ref().map(|t| t.link.clone()),
        };
        let bytes = Arc::new(encode(&node));
        ensure!(bytes.len() <= PAGE, "typed path fixed page bound");
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
            .context("typed path working object overflow")?;
        let bytes_count = lb
            .checked_add(rb)
            .and_then(|n| n.checked_add(bytes.len() as u64))
            .and_then(|n| n.checked_add(value.as_ref().map_or(0, |v| v.len() as u64)))
            .context("typed path working byte overflow")?;
        ensure!(
            objects <= WORK_OBJECTS && bytes_count <= WORK_BYTES,
            "typed path working capacity exhausted; no publication"
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
    fn leaf(&self, value: T) -> Result<Tree> {
        value.validate(self.home())?;
        let e = value.entry(self.currency());
        let bytes = Arc::new(rld_protocol::codec::encode_bounded(&value, T::MAX_BYTES)?);
        self.make(Some(e), Some(bytes), None, None)
    }
    fn branch(&self, l: Tree, r: Tree) -> Result<Tree> {
        self.make(None, None, Some(l), Some(r))
    }
    fn insert_at(&self, root: &Option<Tree>, value: T) -> Result<Tree> {
        let Some(t) = root else {
            return self.leaf(value);
        };
        let key = value.entry(self.currency()).key;
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
        let l = read.left.context("typed path left")?;
        let r = read.right.context("typed path right")?;
        if merkle::bit(key, u8::try_from(t.link.depth)?) {
            self.branch(l, self.insert_at(&Some(r), value)?)
        } else {
            self.branch(self.insert_at(&Some(l), value)?, r)
        }
    }
    fn replace_at(&self, t: &Tree, value: T) -> Result<Tree> {
        let read = self.read(t)?;
        let key = value.entry(self.currency()).key;
        if let Some(entry) = read.node.entry {
            ensure!(entry.key == key, "typed replacement key");
            return self.leaf(value);
        }
        let l = read.left.context("typed replacement left")?;
        let r = read.right.context("typed replacement right")?;
        if merkle::bit(key, u8::try_from(t.link.depth)?) {
            self.branch(l, self.replace_at(&r, value)?)
        } else {
            self.branch(self.replace_at(&l, value)?, r)
        }
    }
    fn remove_at(&self, t: &Tree, key: Id) -> Result<Option<Tree>> {
        let read = self.read(t)?;
        if let Some(e) = read.node.entry {
            ensure!(e.key == key, "typed path removal key");
            return Ok(None);
        }
        let l = read.left.context("typed path remove left")?;
        let r = read.right.context("typed path remove right")?;
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
    fn value(&self, read: Read) -> Result<T> {
        let object = read.node.value.context("typed path leaf value")?;
        let bytes = if let Some(b) = read.value {
            b
        } else {
            self.owner.objects.read(&object, T::MAX_BYTES)?
        };
        ensure!(
            bytes.len() as u64 == object.bytes && Id::digest(bytes.as_slice()) == object.digest,
            "typed path value identity"
        );
        let value: T = decode(bytes.as_slice(), T::MAX_BYTES)?;
        value.validate(self.home())?;
        ensure!(
            Some(value.entry(self.currency())) == read.node.entry,
            "typed path native value commitment"
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
                        .context("typed path rank overflow")?,
                    false,
                ));
            }
            if let Some(e) = read.node.entry {
                return Ok((rank, e.key == key));
            }
            let l = read.left.context("typed path rank left")?;
            let r = read.right.context("typed path rank right")?;
            current = if merkle::bit(key, u8::try_from(t.link.depth)?) {
                rank = rank
                    .checked_add(l.link.count)
                    .context("typed path rank overflow")?;
                Some(r)
            } else {
                Some(l)
            };
        }
        anyhow::bail!("typed path rank depth")
    }
    fn at(&self, index: u64) -> Result<(Membership, T)> {
        ensure!(index < self.count(), "typed path ordinal");
        let mut t = self.root.clone().context("typed path root")?;
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
                ensure!(rank == 0, "typed path leaf rank");
                let member = Membership {
                    entry: e.clone(),
                    path,
                };
                merkle::verify(self.currency(), &self.owner.tag, self.root(), &member)?;
                return Ok((member, self.value(read)?));
            }
            ensure!(path.depths.len() < 64, "typed path path depth");
            let l = read.left.context("typed path proof left")?;
            let r = read.right.context("typed path proof right")?;
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
impl<T: Value> Paths<T> {
    pub(crate) fn currency(&self) -> Id {
        self.owner.currency
    }
    pub(crate) fn home(&self) -> Id {
        self.owner.home
    }
    pub(crate) fn count(&self) -> u64 {
        self.root.as_ref().map_or(0, |t| t.link.count)
    }
    pub(crate) fn root(&self) -> Id {
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
    pub(crate) fn get(&self, key: Id) -> Result<Option<T>> {
        let (rank, found) = self.rank(key)?;
        if found {
            let (m, v) = self.at(rank)?;
            ensure!(m.entry.key == key, "typed path lookup key");
            Ok(Some(v))
        } else {
            self.access(key)?;
            Ok(None)
        }
    }
    pub(crate) fn insert_path(&self, value: T) -> Result<Arc<Self>> {
        let root = self.insert_at(&self.root, value)?;
        ensure!(
            self.count().checked_add(1) == Some(root.link.count),
            "typed path insertion cardinality"
        );
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: Some(root),
            marker: std::marker::PhantomData,
        }))
    }
    pub(crate) fn replace_path(&self, value: T) -> Result<Arc<Self>> {
        let entry = value.entry(self.currency());
        let member = self
            .access(entry.key)?
            .0
            .context("typed replacement missing")?;
        let expected = merkle::replace_member(
            self.currency(),
            &self.owner.tag,
            self.root(),
            &entry,
            &member,
        )?;
        let root = self.replace_at(self.root.as_ref().context("typed replacement root")?, value)?;
        let next = Self {
            owner: self.owner.clone(),
            root: Some(root),
            marker: std::marker::PhantomData,
        };
        ensure!(
            next.root() == expected && next.count() == self.count(),
            "typed complete/compact replacement root/count"
        );
        Ok(Arc::new(next))
    }
    pub(crate) fn spend_path(&self, key: Id) -> Result<(Arc<Self>, Option<T>)> {
        let Some(value) = self.get(key)? else {
            return Ok((Arc::new(self.clone()), None));
        };
        let member = self.access(key)?.0.context("typed path spend member")?;
        let expected =
            merkle::remove_member(self.currency(), &self.owner.tag, self.root(), &member)?;
        let root = self.remove_at(self.root.as_ref().context("typed path spend root")?, key)?;
        let next = Self {
            owner: self.owner.clone(),
            root,
            marker: std::marker::PhantomData,
        };
        ensure!(
            next.root() == expected && self.count().checked_sub(1) == Some(next.count()),
            "typed path complete/compact removal root"
        );
        Ok((Arc::new(next), Some(value)))
    }
    pub(crate) fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
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
    pub(crate) fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_> {
        Box::new(Records {
            store: self.clone(),
            stack: self.root.clone().into_iter().collect(),
            remaining: self.count(),
            failed: false,
        })
    }
    pub(crate) fn seal_path(&self) -> Result<Arc<Self>> {
        let mut stack: Vec<_> = self.root.clone().into_iter().collect();
        while let Some(t) = stack.pop() {
            let Some(w) = &t.work else { continue };
            let read = self.read(&t)?;
            if let Some(value) = &w.value {
                let object = read.node.value.context("typed path seal value")?;
                ensure!(
                    self.owner
                        .objects
                        .put(value.as_ref().clone(), T::MAX_BYTES)?
                        == object,
                    "typed path sealed value identity"
                );
            }
            ensure!(
                self.owner.objects.put(w.bytes.as_ref().clone(), PAGE)? == t.link.object,
                "typed path sealed page identity"
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
            marker: std::marker::PhantomData,
        }))
    }
    pub(crate) fn snapshot(&self) -> Result<Vec<u8>> {
        ensure!(usage(&self.root) == (0, 0), "unsealed UTXO observation");
        Ok(encode(&Snapshot {
            format: T::FORMAT.into(),
            currency: self.currency(),
            home: self.home(),
            genesis: self.owner.genesis,
            root: self.root.as_ref().map(|t| t.link.clone()),
        }))
    }
    pub(crate) fn historical_path(&self, b: &[u8]) -> Result<Arc<Self>> {
        let s: Snapshot = decode(b, 4096)?;
        ensure!(
            s.format == T::FORMAT
                && s.currency == self.currency()
                && s.home == self.home()
                && s.genesis == self.owner.genesis,
            "typed path observation context"
        );
        let next = Self {
            owner: self.owner.clone(),
            root: s.root.map(frozen),
            marker: std::marker::PhantomData,
        };
        if let Some(t) = &next.root {
            next.read(t)?;
        }
        Ok(Arc::new(next))
    }
    pub(crate) fn empty_path(&self) -> Arc<Self> {
        Arc::new(Self {
            owner: self.owner.clone(),
            root: None,
            marker: std::marker::PhantomData,
        })
    }
}
struct Records<T: Value> {
    store: Paths<T>,
    stack: Vec<Tree>,
    remaining: u64,
    failed: bool,
}
impl<T: Value> Iterator for Records<T> {
    type Item = Result<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            let Some(t) = self.stack.pop() else {
                if self.remaining != 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("typed path stream incomplete")));
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
                    return Some(Err(anyhow::anyhow!("typed path stream overflow")));
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
                return Some(Err(anyhow::anyhow!("typed path stream branch")));
            }
        }
    }
}
