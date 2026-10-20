//! Rebuildable disk material for exact authenticated native checkpoints.
//! Neither a storage digest nor a manifest is monetary authority. Every read
//! reconstructs the native root/proof against a caller-retained checkpoint.
use crate::{
    runtime::Initial,
    store::{MAX_RECORD, private_create, read_bounded, sync_dir},
};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use rld_protocol::{
    codec::{Id, decode, encode, hash},
    merkle::{self, Absence, Entry, Membership},
    model::{Certified, Checkpoint, Currency, StateWitness},
    record,
    state::{COLLECTIONS, State},
};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const FORMAT: &str = "RLD-STATE-WITNESS-INDEX-3";
const CHUNK: usize = 1024 * 1024;
const LEAF: usize = 128;
const MANIFEST_LIMIT: usize = 256 * 1024;
const FILE_LIMIT: u64 = 65536;
const BYTE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
record!(Object {digest:Id => 0, bytes:u64 => 1});
record!(Link {object:Object => 0,count:u64 => 1,tree:Id => 2,first:Id => 3,last:Id => 4});
record!(Page {format:String => 0,currency:Id => 1,domain:Id => 2,collection:String => 3,count:u64 => 4,entries:Vec<Entry> => 5,left:Option<Link> => 6,right:Option<Link> => 7});
record!(Table {name:String => 0,root:Option<Link> => 1,commitment:Id => 2});
record!(Manifest {format:String => 0,header:Checkpoint => 1,tables:Vec<Table> => 2,chunks:Vec<Object> => 3,state_bytes:u64 => 4,state_digest:Id => 5});
record!(StateQuery {collection:String => 0,top:Membership => 1,member:Option<Membership> => 2,absence:Option<Absence> => 3});
record!(CertifiedQuery {source:Certified => 0,query:StateQuery => 1});

impl CertifiedQuery {
    pub fn verify(
        &self,
        currency: &Currency,
        expected_checkpoint: Id,
        collection: &str,
        key: Id,
    ) -> Result<()> {
        ensure!(
            self.query.collection == collection,
            "query collection differs from caller's exact requested collection"
        );
        ensure!(
            self.source.header.id() == expected_checkpoint,
            "query checkpoint differs from caller's exact retained target"
        );
        rld_protocol::proof::Verifier { currency }.native(&self.source)?;
        self.query.verify(&self.source.header, key)
    }
}

impl StateQuery {
    /// The caller must independently authenticate this exact checkpoint. This
    /// verifies a historical record/absence only, never current spendability.
    pub fn verify(&self, header: &Checkpoint, key: Id) -> Result<()> {
        ensure!(
            COLLECTIONS.contains(&self.collection.as_str()),
            "query collection"
        );
        ensure!(
            self.top.entry.key
                == hash(
                    "RLD-COLLECTION",
                    header.currency,
                    &(header.domain, self.collection.as_str())
                ),
            "query collection binding"
        );
        merkle::verify(
            header.currency,
            &format!("{}/state", header.domain),
            header.new_root,
            &self.top,
        )?;
        let tag = format!("{}/{}", header.domain, self.collection);
        match (&self.member, &self.absence) {
            (Some(p), None) => {
                ensure!(p.entry.key == key, "query key");
                merkle::verify(header.currency, &tag, self.top.entry.value, p)?;
            }
            (None, Some(p)) => {
                merkle::verify_absent(header.currency, &tag, self.top.entry.value, key, p)?
            }
            _ => bail!("query must have exactly one inclusion or absence"),
        }
        Ok(())
    }
    pub fn membership(self) -> Result<StateWitness> {
        Ok(StateWitness {
            collection: self.collection,
            entry: self.member.context("state key is absent")?,
            top: self.top,
        })
    }
}
struct Usage {
    bytes: u64,
    files: u64,
    serial: u64,
}
pub struct StateIndex {
    root: PathBuf,
    currency: Id,
    domain: Id,
    nonce: Id,
    usage: Mutex<Usage>,
    issue: Mutex<Option<String>>,
    _lock: File,
}
fn split(entries: &[Entry]) -> Result<usize> {
    let depth = merkle::branch_depth(entries[0].key, entries[entries.len() - 1].key)?;
    let m = entries.partition_point(|e| !merkle::bit(e.key, depth));
    ensure!(m > 0 && m < entries.len(), "derived prefix partition");
    Ok(m)
}
fn native_tree(c: Id, tag: &str, entries: &[Entry]) -> Result<Id> {
    Ok(merkle::Map::from_entries(c, tag, entries)?.tree_hash())
}
fn map_root(c: Id, tag: &str, root: Option<&Link>) -> Id {
    let (count, tree) = root.map_or_else(|| (0, merkle::empty_hash(c, tag)), |r| (r.count, r.tree));
    merkle::root_hash(c, tag, count, tree)
}
impl StateIndex {
    pub(crate) fn open(root: &Path, initial: &Initial) -> Result<Arc<Self>> {
        ensure!(!root.is_symlink(), "state index root symlink");
        let fresh = !root.exists();
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fresh {
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(root.join("LOCK"))?;
        lock.try_lock_exclusive()
            .context("state index is already in use")?;
        let currency = initial.currency.id();
        let domain = initial.genesis.configuration.domain;
        let binding = encode(&(
            FORMAT,
            currency,
            domain,
            rld_protocol::state::genesis_id(currency, &initial.genesis),
        ));
        let path = root.join("BINDING.cbor");
        if path.exists() {
            ensure!(
                read_bounded(&path, 1024)? == binding,
                "state index network/genesis binding"
            );
        } else {
            ensure!(
                fs::read_dir(root)?.all(|e| e.is_ok_and(|e| e.file_name() == "LOCK")),
                "unbound state index: preserve and use a fresh derived directory"
            );
            private_create(&path, &binding)?;
        }
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("checkpoints"))?;
        sync_dir(root)?;
        let (mut bytes, mut files) = (0u64, 0u64);
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name == "objects" || name == "checkpoints" {
                ensure!(entry.file_type()?.is_dir(), "derived index directory type");
            } else {
                ensure!(
                    (name == "LOCK" || name == "BINDING.cbor") && entry.file_type()?.is_file(),
                    "unexpected state index root entry; preserve unchanged"
                );
                bytes = bytes
                    .checked_add(entry.metadata()?.len())
                    .context("state index root bytes overflow")?;
                files = files
                    .checked_add(1)
                    .context("state index root file overflow")?;
            }
        }
        for directory in ["objects", "checkpoints"] {
            for entry in fs::read_dir(root.join(directory))? {
                let entry = entry?;
                ensure!(
                    entry.file_type()?.is_file(),
                    "unexpected derived index entry"
                );
                bytes = bytes
                    .checked_add(entry.metadata()?.len())
                    .context("state index byte overflow")?;
                files = files.checked_add(1).context("state index file overflow")?;
                ensure!(
                    files <= FILE_LIMIT,
                    "derived index file budget exhausted; ledger remains authoritative"
                );
            }
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        Ok(Arc::new(Self {
            root: root.into(),
            currency,
            domain,
            nonce: Id(nonce),
            usage: Mutex::new(Usage {
                bytes,
                files,
                serial: 0,
            }),
            issue: Mutex::new(None),
            _lock: lock,
        }))
    }
    pub fn issue(&self) -> Option<String> {
        self.issue.lock().ok().and_then(|v| v.clone())
    }
    pub(crate) fn contains(&self, h: &Checkpoint) -> Result<bool> {
        Ok(self.manifest(h)?.is_some())
    }
    pub(crate) fn writable(&self) -> Result<()> {
        let usage = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("state index unavailable"))?;
        ensure!(
            usage.files < FILE_LIMIT && usage.bytes < BYTE_LIMIT,
            "derived state index full; native data retained"
        );
        Ok(())
    }
    pub(crate) fn note(&self, error: &anyhow::Error) {
        if let Ok(mut v) = self.issue.lock() {
            *v = Some(error.to_string());
        }
    }
    fn object_path(&self, object: &Object) -> PathBuf {
        self.root
            .join("objects")
            .join(format!("{}.blob", object.digest))
    }
    fn read(&self, object: &Object) -> Result<Vec<u8>> {
        ensure!(
            object.bytes > 0 && object.bytes <= CHUNK as u64,
            "derived object byte bound"
        );
        let bytes = read_bounded(&self.object_path(object), CHUNK)?;
        ensure!(
            bytes.len() as u64 == object.bytes && Id::digest(&bytes) == object.digest,
            "derived object digest/size"
        );
        Ok(bytes)
    }
    fn write(&self, directory: &str, name: &str, bytes: &[u8]) -> Result<()> {
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("state index unavailable"))?;
        let path = self.root.join(directory).join(name);
        if path.exists() {
            ensure!(
                read_bounded(&path, bytes.len())? == bytes,
                "changed derived index object: preserve original"
            );
            File::open(path)?.sync_all()?;
            sync_dir(&self.root.join(directory))?;
            return Ok(());
        }
        ensure!(
            usage.files < FILE_LIMIT
                && usage
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .is_some_and(|n| n <= BYTE_LIMIT),
            "derived state index capacity exhausted; complete ledger retained"
        );
        usage.serial = usage
            .serial
            .checked_add(1)
            .context("state index publication count exhaustion")?;
        usage.files += 1;
        usage.bytes += bytes.len() as u64;
        let pending = self
            .root
            .join(directory)
            .join(format!(".partial-{}-{}", self.nonce, usage.serial));
        // Reserve conservatively before writing. Failed partial files remain;
        // reopening recounts actual retained bytes. No native evidence is pruned.
        private_create(&pending, bytes)?;
        sync_dir(&self.root.join(directory))?;
        fs::rename(pending, path)?;
        sync_dir(&self.root.join(directory))
    }
    fn put(&self, bytes: &[u8]) -> Result<Object> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= CHUNK,
            "derived object bound"
        );
        let object = Object {
            digest: Id::digest(bytes),
            bytes: bytes.len() as u64,
        };
        self.write("objects", &format!("{}.blob", object.digest), bytes)?;
        Ok(object)
    }
    fn build(&self, collection: &str, entries: &[Entry]) -> Result<Option<Link>> {
        if entries.is_empty() {
            return Ok(None);
        }
        ensure!(
            entries.windows(2).all(|w| w[0].key < w[1].key),
            "state index map order"
        );
        let tag = format!("{}/{}", self.domain, collection);
        let (left, right, body, tree) = if entries.len() <= LEAF {
            (
                None,
                None,
                entries.to_vec(),
                native_tree(self.currency, &tag, entries)?,
            )
        } else {
            let m = split(entries)?;
            let left = self
                .build(collection, &entries[..m])?
                .context("left subtree")?;
            let right = self
                .build(collection, &entries[m..])?
                .context("right subtree")?;
            let depth = merkle::branch_depth(entries[0].key, entries[entries.len() - 1].key)?;
            let tree = merkle::branch_hash(
                self.currency,
                &tag,
                depth,
                entries[0].key,
                left.tree,
                left.count,
                right.tree,
                right.count,
            );
            (Some(left), Some(right), vec![], tree)
        };
        let page = Page {
            format: FORMAT.into(),
            currency: self.currency,
            domain: self.domain,
            collection: collection.into(),
            count: entries.len() as u64,
            entries: body,
            left,
            right,
        };
        let object = self.put(&encode(&page))?;
        Ok(Some(Link {
            object,
            count: entries.len() as u64,
            tree,
            first: entries[0].key,
            last: entries[entries.len() - 1].key,
        }))
    }
    fn top(&self, tables: &[Table]) -> Result<Vec<Entry>> {
        ensure!(
            tables.len() == COLLECTIONS.len()
                && tables.iter().zip(COLLECTIONS).all(|(t, n)| t.name == *n),
            "derived collection inventory"
        );
        let mut top = Vec::new();
        for t in tables {
            if t.name != "applied" {
                ensure!(
                    map_root(
                        self.currency,
                        &format!("{}/{}", self.domain, t.name),
                        t.root.as_ref()
                    ) == t.commitment,
                    "derived table commitment"
                );
            } else {
                ensure!(
                    t.root.is_none(),
                    "applied map uses authenticated live storage"
                );
            }
            top.push(Entry {
                key: hash(
                    "RLD-COLLECTION",
                    self.currency,
                    &(self.domain, t.name.as_str()),
                ),
                value: t.commitment,
            });
        }
        top.sort_by_key(|e| e.key);
        Ok(top)
    }
    fn manifest_path(&self, h: &Checkpoint) -> PathBuf {
        self.root
            .join("checkpoints")
            .join(format!("{}.cbor", h.id()))
    }
    fn manifest(&self, h: &Checkpoint) -> Result<Option<Manifest>> {
        ensure!(
            h.currency == self.currency && h.domain == self.domain,
            "derived checkpoint home"
        );
        let path = self.manifest_path(h);
        if !path.exists() {
            return Ok(None);
        }
        let m: Manifest = decode(&read_bounded(&path, MANIFEST_LIMIT)?, MANIFEST_LIMIT)?;
        ensure!(
            m.format == FORMAT
                && m.header == *h
                && m.state_bytes > 0
                && m.state_bytes <= MAX_RECORD as u64
                && m.chunks.len() <= MAX_RECORD / CHUNK + 1,
            "derived checkpoint profile/bounds"
        );
        ensure!(
            m.chunks.iter().try_fold(0u64, |n, r| {
                ensure!(
                    r.bytes > 0 && r.bytes <= CHUNK as u64,
                    "derived chunk bounds"
                );
                n.checked_add(r.bytes)
                    .context("derived state length overflow")
            })? == m.state_bytes,
            "derived state length"
        );
        ensure!(
            merkle::root(
                self.currency,
                &format!("{}/state", self.domain),
                &self.top(&m.tables)?
            )? == h.new_root,
            "derived index differs from retained native root"
        );
        Ok(Some(m))
    }
    pub(crate) fn publish(&self, state: &State, h: &Checkpoint) -> Result<()> {
        ensure!(
            state.currency == self.currency
                && state.domain == self.domain
                && state.sequence == h.sequence
                && h.currency == self.currency
                && h.domain == self.domain
                && state.root()? == h.new_root,
            "snapshot does not match authenticated native checkpoint"
        );
        let mut material = state.clone();
        material.applied = rld_protocol::applied::AppliedIndex::new(
            self.currency,
            &format!("{}/applied", self.domain),
        );
        let bytes = rld_protocol::codec::encode_bounded(&material, MAX_RECORD)?;
        ensure!(
            bytes.len() <= MAX_RECORD,
            "snapshot exceeds native witness byte bound"
        );
        let mut chunks = vec![];
        for chunk in bytes.chunks(CHUNK) {
            chunks.push(self.put(chunk)?);
        }
        let mut tables = vec![];
        let native_top = state.top()?;
        for &name in COLLECTIONS {
            tables.push(Table {
                name: name.into(),
                root: if name == "applied" {
                    None
                } else {
                    self.build(name, &state.collection(name)?)?
                },
                commitment: native_top
                    .iter()
                    .find(|e| e.key == hash("RLD-COLLECTION", self.currency, &(self.domain, name)))
                    .context("native collection root")?
                    .value,
            });
        }
        ensure!(
            merkle::root(
                self.currency,
                &format!("{}/state", self.domain),
                &self.top(&tables)?
            )? == h.new_root,
            "disk index root reconstruction"
        );
        let m = Manifest {
            format: FORMAT.into(),
            header: h.clone(),
            tables,
            chunks,
            state_bytes: bytes.len() as u64,
            state_digest: Id::digest(&bytes),
        };
        let encoded = encode(&m);
        ensure!(encoded.len() <= MANIFEST_LIMIT, "derived manifest bound");
        self.write("checkpoints", &format!("{}.cbor", h.id()), &encoded)
    }
    pub(crate) fn load(
        &self,
        h: &Checkpoint,
        applied: rld_protocol::applied::AppliedIndex,
    ) -> Result<Option<State>> {
        let Some(m) = self.manifest(h)? else {
            return Ok(None);
        };
        let mut bytes = Vec::with_capacity(usize::try_from(m.state_bytes)?);
        for chunk in &m.chunks {
            bytes.extend_from_slice(&self.read(chunk)?);
        }
        ensure!(
            Id::digest(&bytes) == m.state_digest,
            "derived complete state digest"
        );
        let mut state: State = decode(&bytes, MAX_RECORD)?;
        ensure!(
            state.applied.is_empty()
                && applied.is_complete()
                && applied.commitment(self.currency, &format!("{}/applied", self.domain))?
                    == m.tables
                        .iter()
                        .find(|t| t.name == "applied")
                        .context("applied collection")?
                        .commitment,
            "snapshot applied material binding"
        );
        state.applied = applied;
        state.invariants()?;
        ensure!(
            state.currency == h.currency
                && state.domain == h.domain
                && state.sequence == h.sequence
                && state.root()? == h.new_root,
            "derived complete state native binding"
        );
        Ok(Some(state))
    }
    fn page(&self, collection: &str, r: &Link) -> Result<Page> {
        ensure!(
            r.count > 0 && r.count <= MAX_RECORD as u64 && r.first <= r.last,
            "derived subtree bounds"
        );
        let p: Page = decode(&self.read(&r.object)?, CHUNK)?;
        ensure!(
            p.format == FORMAT
                && p.currency == self.currency
                && p.domain == self.domain
                && p.collection == collection
                && p.count == r.count,
            "derived page binding"
        );
        let tag = format!("{}/{}", self.domain, collection);
        match (&p.left, &p.right) {
            (None, None) => {
                ensure!(
                    p.entries.len() > 0
                        && p.entries.len() <= LEAF
                        && p.entries.len() as u64 == r.count
                        && p.entries.windows(2).all(|w| w[0].key < w[1].key)
                        && p.entries[0].key == r.first
                        && p.entries[p.entries.len() - 1].key == r.last
                        && native_tree(self.currency, &tag, &p.entries)? == r.tree,
                    "derived leaf authentication"
                );
            }
            (Some(l), Some(right)) => {
                let depth = merkle::branch_depth(r.first, r.last)?;
                ensure!(
                    r.count > LEAF as u64
                        && p.entries.is_empty()
                        && l.count > 0
                        && right.count > 0
                        && l.count.checked_add(right.count) == Some(r.count)
                        && l.first == r.first
                        && right.last == r.last
                        && l.first <= l.last
                        && l.last < right.first
                        && right.first <= right.last
                        && !merkle::bit(l.first, depth)
                        && !merkle::bit(l.last, depth)
                        && merkle::bit(right.first, depth)
                        && merkle::bit(right.last, depth)
                        && merkle::prefix(l.first, depth) == merkle::prefix(right.last, depth)
                        && merkle::branch_hash(
                            self.currency,
                            &tag,
                            depth,
                            r.first,
                            l.tree,
                            l.count,
                            right.tree,
                            right.count
                        ) == r.tree,
                    "derived branch authentication"
                );
            }
            _ => bail!("incomplete derived branch"),
        }
        Ok(p)
    }
    fn at(&self, collection: &str, root: &Link, index: u64) -> Result<Membership> {
        ensure!(index < root.count, "derived rank bound");
        fn walk(s: &StateIndex, c: &str, r: &Link, i: u64, visited: usize) -> Result<Membership> {
            ensure!(visited <= merkle::MAX_PATH, "derived path bound");
            let p = s.page(c, r)?;
            if let (Some(l), Some(right)) = (&p.left, &p.right) {
                let mut member = if i < l.count {
                    walk(s, c, l, i, visited + 1)?
                } else {
                    walk(s, c, right, i - l.count, visited + 1)?
                };
                let sibling = if i < l.count { right } else { l };
                member.path.siblings.insert(0, sibling.tree);
                member
                    .path
                    .depths
                    .insert(0, merkle::branch_depth(r.first, r.last)?);
                member.path.counts.insert(0, sibling.count);
                ensure!(
                    member.path.siblings.len() <= merkle::MAX_PATH,
                    "derived complete path bound"
                );
                Ok(member)
            } else {
                merkle::prove(
                    s.currency,
                    &format!("{}/{}", s.domain, c),
                    &p.entries,
                    usize::try_from(i)?,
                )
            }
        }
        let mut member = walk(self, collection, root, index, 0)?;
        member.path.index = index;
        member.path.count = root.count;
        merkle::verify(
            self.currency,
            &format!("{}/{}", self.domain, collection),
            map_root(
                self.currency,
                &format!("{}/{}", self.domain, collection),
                Some(root),
            ),
            &member,
        )?;
        Ok(member)
    }
    fn rank(&self, collection: &str, root: &Link, key: Id) -> Result<(u64, bool)> {
        let mut r = root.clone();
        let mut base = 0u64;
        let mut visited = 0usize;
        loop {
            ensure!(visited <= merkle::MAX_PATH, "derived rank path bound");
            visited += 1;
            let p = self.page(collection, &r)?;
            if let (Some(left), Some(right)) = (p.left, p.right) {
                if key <= left.last {
                    r = left;
                } else {
                    base = base
                        .checked_add(left.count)
                        .context("derived rank overflow")?;
                    r = right;
                }
            } else {
                return Ok(match p.entries.binary_search_by_key(&key, |e| e.key) {
                    Ok(i) => (base + i as u64, true),
                    Err(i) => (base + i as u64, false),
                });
            }
        }
    }
    pub(crate) fn query(
        &self,
        h: &Checkpoint,
        collection: &str,
        key: Id,
    ) -> Result<Option<StateQuery>> {
        if collection == "applied" {
            return Ok(None);
        }
        let Some(m) = self.manifest(h)? else {
            return Ok(None);
        };
        let table = m
            .tables
            .iter()
            .find(|t| t.name == collection)
            .context("state collection")?;
        let top = self.top(&m.tables)?;
        let topkey = hash("RLD-COLLECTION", self.currency, &(self.domain, collection));
        let top = merkle::prove(
            self.currency,
            &format!("{}/state", self.domain),
            &top,
            top.binary_search_by_key(&topkey, |e| e.key)
                .map_err(|_| anyhow::anyhow!("derived collection position"))?,
        )?;
        let mut query = StateQuery {
            collection: collection.into(),
            top,
            member: None,
            absence: None,
        };
        if let Some(root) = &table.root {
            let (rank, present) = self.rank(collection, root, key)?;
            if present {
                query.member = Some(self.at(collection, root, rank)?);
            } else {
                query.absence = Some(Absence {
                    left: if rank > 0 {
                        Some(self.at(collection, root, rank - 1)?)
                    } else {
                        None
                    },
                    right: if rank < root.count {
                        Some(self.at(collection, root, rank)?)
                    } else {
                        None
                    },
                    count: root.count,
                });
            }
        } else {
            query.absence = Some(Absence {
                left: None,
                right: None,
                count: 0,
            });
        }
        // Unauthenticated routing bounds can only guide a lookup. Membership or
        // adjacent-neighbor absence must verify against the native root itself.
        query.verify(h, key)?;
        Ok(Some(query))
    }
}
