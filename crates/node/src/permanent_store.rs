//! Native-root-exact disk operation log. Only empty genesis and verified native
//! mutation create live roots. Historical snapshots come from verified history.
use crate::{
    object_store::{Object, Objects},
    runtime::Initial,
};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, encode},
    merkle::{self, Absence, Membership},
    permanent::Storage,
    record,
    table::{Key, Record},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
const FORMAT: &str = "RLD-PERMANENT-DISK-1";
const NODE_BYTES: usize = 4096;
const PENDING_NODES: usize = 8192;
const PENDING_BYTES: usize = 32 * 1024 * 1024;
record!(Link{object:Object => 0,native:Id => 1,count:u64 => 2,first:Id => 3,last:Id => 4,height:u8 => 5,depth:u16 => 6});
#[derive(minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
struct Node<T> {
    #[n(0)]
    format: String,
    #[n(1)]
    currency: Id,
    #[n(2)]
    domain: Id,
    #[n(3)]
    entry: Option<T>,
    #[n(4)]
    left: Option<Link>,
    #[n(5)]
    right: Option<Link>,
    #[n(6)]
    tag: String,
}
record!(Snapshot{format:String => 0,currency:Id => 1,domain:Id => 2,genesis:Id => 3,root:Option<Link> => 4,tag:String => 5});
struct Owner {
    objects: Arc<Objects>,
    currency: Id,
    domain: Id,
    genesis: Id,
    tag: String,
}
#[derive(Clone)]
pub(crate) struct DiskPermanent<T> {
    owner: Arc<Owner>,
    root: Option<Link>,
    pending: Arc<BTreeMap<Id, Arc<Vec<u8>>>>,
    marker: std::marker::PhantomData<fn() -> T>,
}
impl<T: Record + minicbor::Encode<()> + for<'b> minicbor::Decode<'b, ()> + Send + Sync + 'static>
    std::fmt::Debug for DiskPermanent<T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskPermanent")
            .field("currency", &self.owner.currency)
            .field("domain", &self.owner.domain)
            .field("count", &self.count())
            .field("native_root", &self.root())
            .finish()
    }
}
impl<T: Record + minicbor::Encode<()> + for<'b> minicbor::Decode<'b, ()> + Send + Sync + 'static>
    DiskPermanent<T>
{
    pub(crate) fn empty(objects: Arc<Objects>, initial: &Initial, name: &str) -> Result<Self> {
        let currency = initial.currency.id();
        let domain = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        Ok(Self {
            owner: Arc::new(Owner {
                objects,
                currency,
                domain,
                genesis,
                tag: format!("{domain}/{name}"),
            }),
            root: None,
            pending: Arc::new(BTreeMap::new()),
            marker: std::marker::PhantomData,
        })
    }
    fn summary(&self, object: Object, node: &Node<T>) -> Result<Link> {
        ensure!(
            node.format == FORMAT
                && node.currency == self.owner.currency
                && node.domain == self.owner.domain
                && node.tag == self.tag(),
            "permanent node context"
        );
        match (&node.entry, &node.left, &node.right) {
            (Some(value), None, None) => {
                let e = value.entry(self.currency());
                ensure!(
                    value.key(self.currency()) == Key::Id(e.key),
                    "permanent direct native key"
                );
                Ok(Link {
                    object,
                    native: merkle::leaf_hash(self.currency(), self.tag(), &e),
                    count: 1,
                    first: e.key,
                    last: e.key,
                    height: 0,
                    depth: 256,
                })
            }
            (None, Some(l), Some(r)) => {
                ensure!(
                    l.count > 0
                        && r.count > 0
                        && l.first <= l.last
                        && r.first <= r.last
                        && l.last < r.first,
                    "permanent branch order/count"
                );
                let depth = merkle::branch_depth(l.first, r.last)?;
                ensure!(
                    l.depth <= 256
                        && r.depth <= 256
                        && l.depth > depth as u16
                        && r.depth > depth as u16
                        && !merkle::bit(l.first, depth)
                        && !merkle::bit(l.last, depth)
                        && merkle::bit(r.first, depth)
                        && merkle::bit(r.last, depth)
                        && merkle::prefix(l.first, depth) == merkle::prefix(r.last, depth),
                    "permanent branch prefix/depth"
                );
                let count = l
                    .count
                    .checked_add(r.count)
                    .context("permanent count exhaustion")?;
                let height = l
                    .height
                    .max(r.height)
                    .checked_add(1)
                    .context("permanent height exhaustion")?;
                ensure!(
                    height as usize <= merkle::MAX_PATH,
                    "permanent native path capacity"
                );
                Ok(Link {
                    object,
                    native: merkle::branch_hash(
                        self.currency(),
                        self.tag(),
                        depth,
                        l.first,
                        l.native,
                        l.count,
                        r.native,
                        r.count,
                    ),
                    count,
                    first: l.first,
                    last: r.last,
                    height,
                    depth: depth as u16,
                })
            }
            _ => anyhow::bail!("incomplete permanent node"),
        }
    }
    fn read(&self, link: &Link) -> Result<Node<T>> {
        let bytes = if let Some(bytes) = self.pending.get(&link.object.digest) {
            ensure!(
                bytes.len() as u64 == link.object.bytes
                    && Id::digest(bytes.as_slice()) == link.object.digest,
                "permanent tentative object identity"
            );
            bytes.clone()
        } else {
            self.owner.objects.read(&link.object, NODE_BYTES)?
        };
        let node: Node<T> = decode(bytes.as_slice(), NODE_BYTES)?;
        ensure!(
            self.summary(link.object.clone(), &node)? == *link,
            "permanent stored summary differs from retained exact object"
        );
        Ok(node)
    }
    fn put(&self, node: Node<T>, pending: &mut BTreeMap<Id, Arc<Vec<u8>>>) -> Result<Link> {
        // Validate before durable publication; the resulting physical hash binds
        // every auxiliary range/height, separately from the exact native hash.
        let bytes = encode(&node);
        let object = Object {
            digest: Id::digest(&bytes),
            bytes: bytes.len() as u64,
        };
        let link = self.summary(object.clone(), &node)?;
        ensure!(bytes.len() <= NODE_BYTES, "permanent node encoding bound");
        if let Some(old) = pending.get(&object.digest) {
            ensure!(
                old.as_slice() == bytes.as_slice(),
                "changed tentative permanent object"
            );
        } else {
            let total = pending.values().try_fold(bytes.len(), |n, b| {
                n.checked_add(b.len())
                    .context("permanent tentative byte overflow")
            })?;
            ensure!(
                pending.len() < PENDING_NODES && total <= PENDING_BYTES,
                "permanent tentative execution budget exhausted; no disk publication"
            );
            pending.insert(object.digest, Arc::new(bytes));
        }
        Ok(link)
    }
    fn leaf(&self, entry: T, pending: &mut BTreeMap<Id, Arc<Vec<u8>>>) -> Result<Link> {
        self.put(
            Node {
                tag: self.tag().into(),
                format: FORMAT.into(),
                currency: self.currency(),
                domain: self.owner.domain,
                entry: Some(entry),
                left: None,
                right: None,
            },
            pending,
        )
    }
    fn branch(
        &self,
        left: Link,
        right: Link,
        pending: &mut BTreeMap<Id, Arc<Vec<u8>>>,
    ) -> Result<Link> {
        self.put(
            Node {
                tag: self.tag().into(),
                format: FORMAT.into(),
                currency: self.currency(),
                domain: self.owner.domain,
                entry: None,
                left: Some(left),
                right: Some(right),
            },
            pending,
        )
    }
    fn insert_at(
        &self,
        root: &Option<Link>,
        entry: T,
        pending: &mut BTreeMap<Id, Arc<Vec<u8>>>,
    ) -> Result<Link> {
        let Some(link) = root else {
            return self.leaf(entry, pending);
        };
        if link.first != entry.entry(self.currency()).key
            && u16::from(merkle::branch_depth(
                link.first,
                entry.entry(self.currency()).key,
            )?) < link.depth
        {
            let new = self.leaf(entry, pending)?;
            return if new.first < link.first {
                self.branch(new, link.clone(), pending)
            } else {
                self.branch(link.clone(), new, pending)
            };
        }
        let node = self.read(link)?;
        if let Some(old) = node.entry {
            ensure!(
                old.entry(self.currency()).key != entry.entry(self.currency()).key,
                "duplicate permanent key"
            );
            anyhow::bail!("permanent insertion prefix inconsistent");
        }
        let left = node.left.context("permanent left child")?;
        let right = node.right.context("permanent right child")?;
        if merkle::bit(entry.entry(self.currency()).key, u8::try_from(link.depth)?) {
            self.branch(left, self.insert_at(&Some(right), entry, pending)?, pending)
        } else {
            self.branch(self.insert_at(&Some(left), entry, pending)?, right, pending)
        }
    }
    fn rank(&self, key: Id) -> Result<(u64, bool)> {
        let mut rank = 0u64;
        let mut current = self.root.clone();
        let mut levels = 0usize;
        while let Some(link) = current {
            ensure!(levels <= merkle::MAX_PATH, "permanent rank depth");
            levels += 1;
            let node = self.read(&link)?;
            if key < link.first {
                break;
            }
            if key > link.last {
                rank = rank
                    .checked_add(link.count)
                    .context("permanent rank overflow")?;
                break;
            }
            if let Some(e) = node.entry {
                return Ok((rank, e.entry(self.currency()).key == key));
            }
            let left = node.left.context("permanent left child")?;
            let right = node.right.context("permanent right child")?;
            if merkle::bit(key, u8::try_from(link.depth)?) {
                rank = rank
                    .checked_add(left.count)
                    .context("permanent rank overflow")?;
                current = Some(right);
            } else {
                current = Some(left);
            }
        }
        Ok((rank, false))
    }
    fn at(&self, index: u64) -> Result<(Membership, T)> {
        ensure!(index < self.count(), "permanent proof rank");
        let mut current = self.root.clone().context("permanent nonempty root")?;
        let mut rank = index;
        let mut path = merkle::Path {
            index,
            count: self.count(),
            siblings: vec![],
            depths: vec![],
            counts: vec![],
        };
        loop {
            let node = self.read(&current)?;
            if let Some(entry) = node.entry {
                ensure!(rank == 0, "permanent proof leaf rank");
                let member = Membership {
                    entry: entry.entry(self.currency()),
                    path,
                };
                merkle::verify(self.currency(), self.tag(), self.root(), &member)?;
                return Ok((member, entry));
            }
            ensure!(
                path.depths.len() < merkle::MAX_PATH,
                "permanent proof path bound"
            );
            let left = node.left.context("permanent left child")?;
            let right = node.right.context("permanent right child")?;
            path.depths.push(u8::try_from(current.depth)?);
            if rank < left.count {
                path.siblings.push(right.native);
                path.counts.push(right.count);
                current = left;
            } else {
                rank -= left.count;
                path.siblings.push(left.native);
                path.counts.push(left.count);
                current = right;
            }
        }
    }
}
impl<T: Record + minicbor::Encode<()> + for<'b> minicbor::Decode<'b, ()> + Send + Sync + 'static>
    Storage<T> for DiskPermanent<T>
{
    fn currency(&self) -> Id {
        self.owner.currency
    }
    fn tag(&self) -> &str {
        &self.owner.tag
    }
    fn root(&self) -> Id {
        merkle::root_hash(
            self.currency(),
            self.tag(),
            self.count(),
            self.root.as_ref().map_or_else(
                || merkle::empty_hash(self.currency(), self.tag()),
                |r| r.native,
            ),
        )
    }
    fn count(&self) -> u64 {
        self.root.as_ref().map_or(0, |r| r.count)
    }
    fn get(&self, id: Id) -> Result<Option<T>> {
        let (rank, found) = self.rank(id)?;
        if !found {
            let (member, absence) = self.access(id)?;
            ensure!(
                member.is_none() && absence.is_some(),
                "permanent absence lookup"
            );
            return Ok(None);
        }
        let (member, value) = self.at(rank)?;
        ensure!(member.entry.key == id, "permanent lookup identity");
        Ok(Some(value))
    }
    fn insert(&self, value: T) -> Result<Arc<dyn Storage<T>>> {
        let mut pending = self.pending.as_ref().clone();
        let root = self.insert_at(&self.root, value, &mut pending)?;
        ensure!(
            self.count().checked_add(1) == Some(root.count),
            "permanent insertion cardinality"
        );
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: Some(root),
            pending: Arc::new(pending),
            marker: std::marker::PhantomData,
        }))
    }
    fn seal(&self) -> Result<Arc<dyn Storage<T>>> {
        let mut needed = BTreeSet::new();
        let mut stack: Vec<_> = self.root.clone().into_iter().collect();
        while let Some(link) = stack.pop() {
            if !self.pending.contains_key(&link.object.digest) || !needed.insert(link.object.digest)
            {
                continue;
            }
            let node = self.read(&link)?;
            if let (Some(l), Some(r)) = (node.left, node.right) {
                stack.push(r);
                stack.push(l);
            }
        }
        for id in needed {
            let bytes = self.pending.get(&id).context("permanent seal object")?;
            ensure!(
                self.owner
                    .objects
                    .put(bytes.as_ref().clone(), NODE_BYTES)?
                    .digest
                    == id,
                "permanent sealed object identity"
            );
        }
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: self.root.clone(),
            pending: Arc::new(BTreeMap::new()),
            marker: std::marker::PhantomData,
        }))
    }
    fn access(&self, id: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        let (rank, found) = self.rank(id)?;
        if found {
            return Ok((Some(self.at(rank)?.0), None));
        }
        let absence = Absence {
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
        merkle::verify_absent(self.currency(), self.tag(), self.root(), id, &absence)?;
        Ok((None, Some(absence)))
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_> {
        Box::new(Records {
            store: self.clone(),
            stack: self.root.clone().into_iter().collect(),
            remaining: self.count(),
            failed: false,
        })
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        ensure!(
            self.pending.is_empty(),
            "tentative permanent root cannot become historical storage anchor"
        );
        Ok(encode(&Snapshot {
            format: FORMAT.into(),
            currency: self.currency(),
            domain: self.owner.domain,
            genesis: self.owner.genesis,
            tag: self.tag().into(),
            root: self.root.clone(),
        }))
    }
    fn historical(&self, bytes: &[u8]) -> Result<Arc<dyn Storage<T>>> {
        let s: Snapshot = decode(bytes, NODE_BYTES)?;
        ensure!(
            s.format == FORMAT
                && s.currency == self.currency()
                && s.domain == self.owner.domain
                && s.genesis == self.owner.genesis
                && s.tag == self.tag(),
            "historical permanent snapshot context"
        );
        let next = Self {
            owner: self.owner.clone(),
            root: s.root,
            pending: Arc::new(BTreeMap::new()),
            marker: std::marker::PhantomData,
        };
        if let Some(link) = &next.root {
            next.read(link)?;
        }
        Ok(Arc::new(next))
    }
    fn empty(&self) -> Arc<dyn Storage<T>> {
        Arc::new(Self {
            owner: self.owner.clone(),
            root: None,
            pending: Arc::new(BTreeMap::new()),
            marker: std::marker::PhantomData,
        })
    }
}
struct Records<T> {
    store: DiskPermanent<T>,
    stack: Vec<Link>,
    remaining: u64,
    failed: bool,
}
impl<T: Record + minicbor::Encode<()> + for<'b> minicbor::Decode<'b, ()> + Send + Sync + 'static>
    Iterator for Records<T>
{
    type Item = Result<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            let Some(link) = self.stack.pop() else {
                if self.remaining != 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("permanent record stream incomplete")));
                }
                return None;
            };
            let node = match self.store.read(&link) {
                Ok(v) => v,
                Err(e) => {
                    self.failed = true;
                    return Some(Err(e));
                }
            };
            if let Some(e) = node.entry {
                if self.remaining == 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("permanent record stream overflow")));
                }
                self.remaining -= 1;
                return Some(Ok(e));
            }
            if let (Some(left), Some(right)) = (node.left, node.right) {
                self.stack.push(right);
                self.stack.push(left);
            } else {
                self.failed = true;
                return Some(Err(anyhow::anyhow!("permanent record stream branch")));
            }
        }
    }
}
