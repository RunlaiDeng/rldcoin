//! Native-root-exact disk operation log. Only empty genesis and verified native
//! mutation create live roots. Historical snapshots come from verified history.
use crate::{
    object_store::{Object, ObjectStatus, Objects},
    runtime::Initial,
};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    applied::{AppliedStep, Storage},
    codec::{Id, decode, encode},
    merkle::{self, Absence, Entry, Membership},
    model::Applied,
    record,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};
const FORMAT: &str = "RLD-APPLIED-DISK-1";
const NODE_BYTES: usize = 4096;
const PENDING_NODES: usize = 8192;
const PENDING_BYTES: usize = 32 * 1024 * 1024;
record!(Link{object:Object => 0,native:Id => 1,count:u64 => 2,first:Id => 3,last:Id => 4,height:u8 => 5,depth:u16 => 6});
record!(Node{format:String => 0,currency:Id => 1,domain:Id => 2,entry:Option<Entry> => 3,left:Option<Link> => 4,right:Option<Link> => 5});
record!(Snapshot{format:String => 0,currency:Id => 1,domain:Id => 2,genesis:Id => 3,root:Option<Link> => 4});
struct Owner {
    objects: Arc<Objects>,
    currency: Id,
    domain: Id,
    genesis: Id,
    tag: String,
}
#[derive(Clone)]
pub(crate) struct AppliedStore {
    owner: Arc<Owner>,
    root: Option<Link>,
    pending: Arc<BTreeMap<Id, Arc<Vec<u8>>>>,
}
impl std::fmt::Debug for AppliedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppliedStore")
            .field("currency", &self.owner.currency)
            .field("domain", &self.owner.domain)
            .field("count", &self.count())
            .field("native_root", &self.root())
            .finish()
    }
}
impl AppliedStore {
    pub(crate) fn open(path: &Path, initial: &Initial) -> Result<Self> {
        let currency = initial.currency.id();
        let domain = initial.genesis.configuration.domain;
        let genesis = rld_protocol::state::genesis_id(currency, &initial.genesis);
        let objects = Objects::open(path, &encode(&(FORMAT, currency, domain, genesis)))?;
        Ok(Self {
            owner: Arc::new(Owner {
                objects,
                currency,
                domain,
                genesis,
                tag: format!("{domain}/applied"),
            }),
            root: None,
            pending: Arc::new(BTreeMap::new()),
        })
    }
    pub(crate) fn status(&self) -> Result<ObjectStatus> {
        self.owner.objects.status()
    }
    fn summary(&self, object: Object, node: &Node) -> Result<Link> {
        ensure!(
            node.format == FORMAT
                && node.currency == self.owner.currency
                && node.domain == self.owner.domain,
            "applied node context"
        );
        match (&node.entry, &node.left, &node.right) {
            (Some(e), None, None) => Ok(Link {
                object,
                native: merkle::leaf_hash(self.currency(), self.tag(), e),
                count: 1,
                first: e.key,
                last: e.key,
                height: 0,
                depth: 256,
            }),
            (None, Some(l), Some(r)) => {
                ensure!(
                    l.count > 0
                        && r.count > 0
                        && l.first <= l.last
                        && r.first <= r.last
                        && l.last < r.first,
                    "applied branch order/count"
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
                    "applied branch prefix/depth"
                );
                let count = l
                    .count
                    .checked_add(r.count)
                    .context("applied count exhaustion")?;
                let height = l
                    .height
                    .max(r.height)
                    .checked_add(1)
                    .context("applied height exhaustion")?;
                ensure!(
                    height as usize <= merkle::MAX_PATH,
                    "applied native path capacity"
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
            _ => anyhow::bail!("incomplete applied node"),
        }
    }
    fn read(&self, link: &Link) -> Result<Node> {
        let bytes = if let Some(bytes) = self.pending.get(&link.object.digest) {
            ensure!(
                bytes.len() as u64 == link.object.bytes
                    && Id::digest(bytes.as_slice()) == link.object.digest,
                "applied tentative object identity"
            );
            bytes.clone()
        } else {
            self.owner.objects.read(&link.object, NODE_BYTES)?
        };
        let node: Node = decode(bytes.as_slice(), NODE_BYTES)?;
        ensure!(
            self.summary(link.object.clone(), &node)? == *link,
            "applied stored summary differs from retained exact object"
        );
        Ok(node)
    }
    fn put(&self, node: Node, pending: &mut BTreeMap<Id, Arc<Vec<u8>>>) -> Result<Link> {
        // Validate before durable publication; the resulting physical hash binds
        // every auxiliary range/height, separately from the exact native hash.
        let bytes = encode(&node);
        let object = Object {
            digest: Id::digest(&bytes),
            bytes: bytes.len() as u64,
        };
        let link = self.summary(object.clone(), &node)?;
        ensure!(bytes.len() <= NODE_BYTES, "applied node encoding bound");
        if let Some(old) = pending.get(&object.digest) {
            ensure!(
                old.as_slice() == bytes.as_slice(),
                "changed tentative applied object"
            );
        } else {
            let total = pending.values().try_fold(bytes.len(), |n, b| {
                n.checked_add(b.len())
                    .context("applied tentative byte overflow")
            })?;
            ensure!(
                pending.len() < PENDING_NODES && total <= PENDING_BYTES,
                "applied tentative execution budget exhausted; no disk publication"
            );
            pending.insert(object.digest, Arc::new(bytes));
        }
        Ok(link)
    }
    fn leaf(&self, entry: Entry, pending: &mut BTreeMap<Id, Arc<Vec<u8>>>) -> Result<Link> {
        self.put(
            Node {
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
        entry: Entry,
        pending: &mut BTreeMap<Id, Arc<Vec<u8>>>,
    ) -> Result<Link> {
        let Some(link) = root else {
            return self.leaf(entry, pending);
        };
        if link.first != entry.key
            && u16::from(merkle::branch_depth(link.first, entry.key)?) < link.depth
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
            ensure!(old.key != entry.key, "duplicate applied key");
            anyhow::bail!("applied insertion prefix inconsistent");
        }
        let left = node.left.context("applied left child")?;
        let right = node.right.context("applied right child")?;
        if merkle::bit(entry.key, u8::try_from(link.depth)?) {
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
            ensure!(levels <= merkle::MAX_PATH, "applied rank depth");
            levels += 1;
            let node = self.read(&link)?;
            if key < link.first {
                break;
            }
            if key > link.last {
                rank = rank
                    .checked_add(link.count)
                    .context("applied rank overflow")?;
                break;
            }
            if let Some(e) = node.entry {
                return Ok((rank, e.key == key));
            }
            let left = node.left.context("applied left child")?;
            let right = node.right.context("applied right child")?;
            if merkle::bit(key, u8::try_from(link.depth)?) {
                rank = rank
                    .checked_add(left.count)
                    .context("applied rank overflow")?;
                current = Some(right);
            } else {
                current = Some(left);
            }
        }
        Ok((rank, false))
    }
    fn at(&self, index: u64) -> Result<Membership> {
        ensure!(index < self.count(), "applied proof rank");
        let mut current = self.root.clone().context("applied nonempty root")?;
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
                ensure!(rank == 0, "applied proof leaf rank");
                let member = Membership { entry, path };
                merkle::verify(self.currency(), self.tag(), self.root(), &member)?;
                return Ok(member);
            }
            ensure!(
                path.depths.len() < merkle::MAX_PATH,
                "applied proof path bound"
            );
            let left = node.left.context("applied left child")?;
            let right = node.right.context("applied right child")?;
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
impl Storage for AppliedStore {
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
    fn get(&self, id: Id) -> Result<Option<Applied>> {
        let proof = self.access(id)?;
        Ok(proof.member.map(|m| Applied {
            id: m.entry.key,
            digest: m.entry.value,
        }))
    }
    fn insert(&self, value: Applied) -> Result<Arc<dyn Storage>> {
        let mut pending = self.pending.as_ref().clone();
        let root = self.insert_at(
            &self.root,
            Entry {
                key: value.id,
                value: value.digest,
            },
            &mut pending,
        )?;
        ensure!(
            self.count().checked_add(1) == Some(root.count),
            "applied insertion cardinality"
        );
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: Some(root),
            pending: Arc::new(pending),
        }))
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
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
            let bytes = self.pending.get(&id).context("applied seal object")?;
            ensure!(
                self.owner
                    .objects
                    .put(bytes.as_ref().clone(), NODE_BYTES)?
                    .digest
                    == id,
                "applied sealed object identity"
            );
        }
        Ok(Arc::new(Self {
            owner: self.owner.clone(),
            root: self.root.clone(),
            pending: Arc::new(BTreeMap::new()),
        }))
    }
    fn access(&self, id: Id) -> Result<AppliedStep> {
        let (rank, found) = self.rank(id)?;
        let step = if found {
            AppliedStep {
                id,
                member: Some(self.at(rank)?),
                absence: None,
            }
        } else {
            let absence = Absence {
                count: self.count(),
                left: if rank > 0 {
                    Some(self.at(rank - 1)?)
                } else {
                    None
                },
                right: if rank < self.count() {
                    Some(self.at(rank)?)
                } else {
                    None
                },
            };
            merkle::verify_absent(self.currency(), self.tag(), self.root(), id, &absence)?;
            AppliedStep {
                id,
                member: None,
                absence: Some(absence),
            }
        };
        Ok(step)
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<Applied>> + Send + '_> {
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
            "tentative applied root cannot become historical storage anchor"
        );
        Ok(encode(&Snapshot {
            format: FORMAT.into(),
            currency: self.currency(),
            domain: self.owner.domain,
            genesis: self.owner.genesis,
            root: self.root.clone(),
        }))
    }
    fn historical(&self, bytes: &[u8]) -> Result<Arc<dyn Storage>> {
        let s: Snapshot = decode(bytes, NODE_BYTES)?;
        ensure!(
            s.format == FORMAT
                && s.currency == self.currency()
                && s.domain == self.owner.domain
                && s.genesis == self.owner.genesis,
            "historical applied snapshot context"
        );
        let next = Self {
            owner: self.owner.clone(),
            root: s.root,
            pending: Arc::new(BTreeMap::new()),
        };
        if let Some(link) = &next.root {
            next.read(link)?;
        }
        Ok(Arc::new(next))
    }
    fn empty(&self) -> Arc<dyn Storage> {
        Arc::new(Self {
            owner: self.owner.clone(),
            root: None,
            pending: Arc::new(BTreeMap::new()),
        })
    }
}
struct Records {
    store: AppliedStore,
    stack: Vec<Link>,
    remaining: u64,
    failed: bool,
}
impl Iterator for Records {
    type Item = Result<Applied>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            let Some(link) = self.stack.pop() else {
                if self.remaining != 0 {
                    self.failed = true;
                    return Some(Err(anyhow::anyhow!("applied record stream incomplete")));
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
                    return Some(Err(anyhow::anyhow!("applied record stream overflow")));
                }
                self.remaining -= 1;
                return Some(Ok(Applied {
                    id: e.key,
                    digest: e.value,
                }));
            }
            if let (Some(left), Some(right)) = (node.left, node.right) {
                self.stack.push(right);
                self.stack.push(left);
            } else {
                self.failed = true;
                return Some(Err(anyhow::anyhow!("applied record stream branch")));
            }
        }
    }
}
