//! Disk-resident immutable index over completely native-verified records.
//! Roots exist only in live authenticated observations, never in an adopted disk
//! manifest. Cold startup reconstructs them through complete journal replay.
use crate::{
    runtime::{Committed, Initial},
    store::{MAX_RECORD, private_create, read_bounded, sync_dir},
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use rld_protocol::{
    codec::{Blob, Id, decode, encode, hash},
    record,
};
use std::{
    collections::VecDeque,
    fs::{self, File},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const FORMAT: &str = "RLD-VERIFIED-HISTORY-INDEX-5";
const WIDTH: usize = 32;
const PAGE_BYTES: usize = 16 * 1024;
const CACHE_BYTES: usize = 32 * 1024 * 1024;
const CACHE_OBJECTS: usize = 128;
// Admission limits on retained derived storage, not monetary history truncation.
const DISK_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const DISK_FILES: u64 = 4_194_304;
record!(Object {digest:Id => 0,bytes:u64 => 1});
record!(Link {object:Object => 0,first:u64 => 1,last:u64 => 2,height:u8 => 3});
record!(Page {format:String => 0,currency:Id => 1,domain:Id => 2,height:u8 => 3,children:Vec<Link> => 4});
record!(HistoryStatus {format:String => 0,records:u64 => 1,accounted_bytes:u64 => 2,accounted_files:u64 => 3,byte_limit:u64 => 4,file_limit:u64 => 5,cache_bytes:u64 => 6,cache_objects:u64 => 7,cache_byte_limit:u64 => 8,cache_object_limit:u64 => 9});
record!(StoredRecord{record:Committed => 0,storage_snapshot:Blob => 1});
struct Cache {
    objects: VecDeque<(Object, Arc<Vec<u8>>)>,
    bytes: usize,
}
struct Usage {
    bytes: u64,
    files: u64,
    serial: u64,
}
struct Disk {
    root: PathBuf,
    currency: Id,
    domain: Id,
    nonce: Id,
    usage: Mutex<Usage>,
    cache: Mutex<Cache>,
    _lock: File,
}
#[derive(Clone)]
pub struct History {
    disk: Arc<Disk>,
    root: Option<Link>,
    len: u64,
    head: Id,
}
fn capacity(height: u8) -> u128 {
    1u128 << (u32::from(height) * 5)
}
fn count(link: &Link) -> Result<u64> {
    link.last
        .checked_sub(link.first)
        .and_then(|n| n.checked_add(1))
        .context("history link range")
}
fn regular_file(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "history object is not a regular private file"
    );
    Ok(())
}
impl Disk {
    fn path(&self, digest: Id) -> PathBuf {
        let name = digest.to_string();
        self.root
            .join("objects")
            .join(&name[..2])
            .join(format!("{}.blob", &name[2..]))
    }
    fn remember(&self, object: &Object, bytes: Arc<Vec<u8>>) -> Result<()> {
        if bytes.len() > CACHE_BYTES {
            return Ok(());
        }
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("history cache unavailable"))?;
        if let Some(i) = cache
            .objects
            .iter()
            .position(|(old, _)| old.digest == object.digest)
        {
            let (old, data) = cache.objects.remove(i).context("history cache position")?;
            ensure!(
                old == *object && data.as_slice() == bytes.as_slice(),
                "changed immutable history cache object"
            );
            cache.bytes -= data.len();
        }
        while cache.objects.len() >= CACHE_OBJECTS || cache.bytes + bytes.len() > CACHE_BYTES {
            let (_, old) = cache
                .objects
                .pop_front()
                .context("history cache eviction")?;
            cache.bytes -= old.len();
        }
        cache.bytes += bytes.len();
        cache.objects.push_back((object.clone(), bytes));
        Ok(())
    }
    fn read(&self, object: &Object, limit: usize) -> Result<Arc<Vec<u8>>> {
        ensure!(
            object.bytes > 0 && object.bytes <= limit as u64,
            "history object read bound"
        );
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow::anyhow!("history cache unavailable"))?;
            if let Some(i) = cache
                .objects
                .iter()
                .position(|(old, _)| old.digest == object.digest)
            {
                let entry = cache.objects.remove(i).context("history cache position")?;
                ensure!(entry.0 == *object, "history cached length mismatch");
                let bytes = entry.1.clone();
                cache.objects.push_back(entry);
                return Ok(bytes);
            }
        }
        let path = self.path(object.digest);
        regular_file(&path)?;
        let bytes = Arc::new(read_bounded(&path, usize::try_from(object.bytes)?)?);
        ensure!(
            bytes.len() as u64 == object.bytes && Id::digest(bytes.as_slice()) == object.digest,
            "history object digest/length mismatch; retain damaged material"
        );
        self.remember(object, bytes.clone())?;
        Ok(bytes)
    }
    fn put(&self, bytes: Vec<u8>) -> Result<Object> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RECORD,
            "history publication byte bound"
        );
        let object = Object {
            digest: Id::digest(&bytes),
            bytes: bytes.len() as u64,
        };
        let path = self.path(object.digest);
        let parent = path.parent().context("history shard parent")?;
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("history storage unavailable"))?;
        if !parent.exists() {
            fs::create_dir(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            sync_dir(&self.root.join("objects"))?;
        }
        ensure!(
            fs::symlink_metadata(parent)?.file_type().is_dir(),
            "history shard directory type"
        );
        if path.exists() {
            regular_file(&path)?;
            ensure!(
                read_bounded(&path, bytes.len())? == bytes,
                "changed retained history object; preserve it"
            );
            File::open(&path)?.sync_all()?;
            sync_dir(parent)?;
        } else {
            ensure!(
                usage.files < DISK_FILES
                    && usage
                        .bytes
                        .checked_add(object.bytes)
                        .is_some_and(|n| n <= DISK_BYTES),
                "verified history index capacity exhausted; retain authoritative journal and all objects"
            );
            usage.serial = usage
                .serial
                .checked_add(1)
                .context("history publication count exhaustion")?;
            usage.files += 1;
            usage.bytes += object.bytes;
            let pending = parent.join(format!(".partial-{}-{}", self.nonce, usage.serial));
            private_create(&pending, &bytes)?;
            sync_dir(parent)?;
            fs::rename(&pending, &path)?;
            sync_dir(parent)?;
        }
        drop(usage);
        self.remember(&object, Arc::new(bytes))?;
        Ok(object)
    }
    fn page(&self, link: &Link) -> Result<Page> {
        ensure!(
            (1..=13).contains(&link.height)
                && link.first > 0
                && u128::from(count(link)?) <= capacity(link.height),
            "history page range/height"
        );
        let p: Page = decode(self.read(&link.object, PAGE_BYTES)?.as_slice(), PAGE_BYTES)?;
        ensure!(
            p.format == FORMAT
                && p.currency == self.currency
                && p.domain == self.domain
                && p.height == link.height
                && !p.children.is_empty()
                && p.children.len() <= WIDTH,
            "history page binding/count"
        );
        ensure!(
            p.children[0].first == link.first
                && p.children.last().context("history page children")?.last == link.last,
            "history page endpoints"
        );
        for (i, child) in p.children.iter().enumerate() {
            let n = count(child)?;
            ensure!(
                child.height.checked_add(1) == Some(link.height)
                    && child.first > 0
                    && u128::from(n) <= capacity(child.height)
                    && child.object.bytes > 0
                    && child.object.bytes
                        <= if child.height == 0 {
                            MAX_RECORD as u64
                        } else {
                            PAGE_BYTES as u64
                        },
                "history child bounds"
            );
            ensure!(
                i + 1 == p.children.len() || u128::from(n) == capacity(child.height),
                "history nonfinal child not full"
            );
            if i > 0 {
                ensure!(
                    p.children[i - 1].last.checked_add(1) == Some(child.first),
                    "history child sequence gap"
                );
            }
        }
        Ok(p)
    }
    fn branch(&self, height: u8, children: Vec<Link>) -> Result<Link> {
        ensure!(
            (1..=13).contains(&height) && !children.is_empty() && children.len() <= WIDTH,
            "history branch construction bounds"
        );
        let first = children[0].first;
        let last = children.last().context("history branch children")?.last;
        let bytes = encode(&Page {
            format: FORMAT.into(),
            currency: self.currency,
            domain: self.domain,
            height,
            children,
        });
        ensure!(bytes.len() <= PAGE_BYTES, "history page encoding bound");
        let link = Link {
            object: self.put(bytes)?,
            first,
            last,
            height,
        };
        self.page(&link)?;
        Ok(link)
    }
    fn path_to(&self, height: u8, record: Link) -> Result<Link> {
        if height == 0 {
            Ok(record)
        } else {
            self.branch(height, vec![self.path_to(height - 1, record)?])
        }
    }
    fn append(&self, root: &Link, record: Link) -> Result<Link> {
        ensure!(
            root.last.checked_add(1) == Some(record.first),
            "history append continuity"
        );
        let mut page = self.page(root)?;
        let tail = page.children.last().context("history tail child")?;
        if u128::from(count(tail)?) < capacity(tail.height) {
            let next = self.append(tail, record)?;
            *page.children.last_mut().context("history mutable tail")? = next;
        } else {
            ensure!(
                page.children.len() < WIDTH,
                "history branch append capacity"
            );
            page.children.push(self.path_to(root.height - 1, record)?);
        }
        self.branch(root.height, page.children)
    }
}
impl History {
    pub(crate) fn open(root: &Path, initial: &Initial) -> Result<Self> {
        ensure!(!root.is_symlink(), "history index root symlink");
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
        let lock_path = root.join("LOCK");
        if lock_path.exists() {
            regular_file(&lock_path)?;
        }
        let lock = options.open(lock_path)?;
        lock.try_lock_exclusive()
            .context("history index already in use")?;
        let currency = initial.currency.id();
        let domain = initial.genesis.configuration.domain;
        let head = rld_protocol::state::genesis_id(currency, &initial.genesis);
        let binding = encode(&(FORMAT, currency, domain, head));
        let binding_path = root.join("BINDING.cbor");
        if binding_path.exists() {
            regular_file(&binding_path)?;
            ensure!(
                read_bounded(&binding_path, 1024)? == binding,
                "history index network/genesis binding"
            );
        } else {
            ensure!(
                fs::read_dir(root)?.all(|e| e.is_ok_and(|e| e.file_name() == "LOCK")),
                "unbound history index; retain and use a fresh private derived directory"
            );
            private_create(&binding_path, &binding)?;
        }
        let objects = root.join("objects");
        fs::create_dir_all(&objects)?;
        ensure!(
            fs::symlink_metadata(&objects)?.file_type().is_dir(),
            "history objects directory type"
        );
        sync_dir(root)?;
        let (mut files, mut bytes) = (0u64, 0u64);
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() == "objects" {
                continue;
            }
            ensure!(
                (entry.file_name() == "LOCK" || entry.file_name() == "BINDING.cbor")
                    && entry.file_type()?.is_file(),
                "unexpected history index entry"
            );
            files += 1;
            bytes = bytes
                .checked_add(entry.metadata()?.len())
                .context("history disk bytes overflow")?;
        }
        for shard in fs::read_dir(&objects)? {
            let shard = shard?;
            let name = shard.file_name();
            let name = name.to_str().context("history shard name")?;
            ensure!(
                shard.file_type()?.is_dir()
                    && name.len() == 2
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "unexpected history shard; retain unchanged"
            );
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                ensure!(
                    entry.file_type()?.is_file(),
                    "unexpected history retained object type"
                );
                files = files
                    .checked_add(1)
                    .context("history disk files overflow")?;
                bytes = bytes
                    .checked_add(entry.metadata()?.len())
                    .context("history disk bytes overflow")?;
                ensure!(
                    files <= DISK_FILES,
                    "history retained file capacity exhausted"
                );
            }
        }
        // Count every retained partial/orphan. Existing valid objects remain readable
        // at capacity; no new object is admitted and no evidence is deleted.
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            disk: Arc::new(Disk {
                root: root.into(),
                currency,
                domain,
                nonce: Id(nonce),
                usage: Mutex::new(Usage {
                    bytes,
                    files,
                    serial: 0,
                }),
                cache: Mutex::new(Cache {
                    objects: VecDeque::new(),
                    bytes: 0,
                }),
                _lock: lock,
            }),
            root: None,
            len: 0,
            head,
        })
    }
    pub fn status(&self) -> Result<HistoryStatus> {
        let usage = self
            .disk
            .usage
            .lock()
            .map_err(|_| anyhow::anyhow!("history storage observation unavailable"))?;
        let cache = self
            .disk
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("history cache observation unavailable"))?;
        Ok(HistoryStatus {
            format: FORMAT.into(),
            records: self.len,
            accounted_bytes: usage.bytes,
            accounted_files: usage.files,
            byte_limit: DISK_BYTES,
            file_limit: DISK_FILES,
            cache_bytes: u64::try_from(cache.bytes)?,
            cache_objects: u64::try_from(cache.objects.len())?,
            cache_byte_limit: CACHE_BYTES as u64,
            cache_object_limit: CACHE_OBJECTS as u64,
        })
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn push(&mut self, value: Committed, storage_snapshot: Vec<u8>) -> Result<()> {
        let next = self
            .len
            .checked_add(1)
            .context("native history count exhaustion")?;
        ensure!(
            value.header.sequence == next
                && value.header.currency == self.disk.currency
                && value.header.domain == self.disk.domain
                && value.header.predecessor == self.head,
            "verified history append identity/predecessor"
        );
        ensure!(
            !storage_snapshot.is_empty() && storage_snapshot.len() <= 4096,
            "verified history applied snapshot bound"
        );
        let head = value.header.id();
        let record = Link {
            object: self.disk.put(encode(&StoredRecord {
                record: value,
                storage_snapshot: Blob(storage_snapshot),
            }))?,
            first: next,
            last: next,
            height: 0,
        };
        let root = if let Some(root) = &self.root {
            if u128::from(self.len) == capacity(root.height) {
                ensure!(root.height < 13, "history index height exhaustion");
                self.disk.branch(
                    root.height + 1,
                    vec![root.clone(), self.disk.path_to(root.height, record)?],
                )?
            } else {
                self.disk.append(root, record)?
            }
        } else {
            ensure!(self.len == 0, "empty history identity");
            record
        };
        self.root = Some(root);
        self.len = next;
        self.head = head;
        Ok(())
    }
    pub fn at(&self, sequence: u64) -> Result<Option<Arc<Committed>>> {
        Ok(self.material(sequence)?.map(|(record, _)| record))
    }
    pub(crate) fn material(&self, sequence: u64) -> Result<Option<(Arc<Committed>, Vec<u8>)>> {
        if sequence == 0 || sequence > self.len {
            return Ok(None);
        }
        let mut link = self.root.clone().context("nonempty history root")?;
        while link.height > 0 {
            let page = self.disk.page(&link)?;
            link = page
                .children
                .into_iter()
                .find(|c| c.first <= sequence && sequence <= c.last)
                .context("history sequence absent from authenticated page")?;
        }
        ensure!(
            link.first == sequence && link.last == sequence,
            "history record exact range"
        );
        let bytes = self.disk.read(&link.object, MAX_RECORD)?;
        let stored: StoredRecord = decode(bytes.as_slice(), MAX_RECORD)?;
        ensure!(
            !stored.storage_snapshot.0.is_empty() && stored.storage_snapshot.0.len() <= 4096,
            "historical applied snapshot bound"
        );
        let record = stored.record;
        ensure!(
            record.header.currency == self.disk.currency
                && record.header.domain == self.disk.domain
                && record.header.sequence == sequence
                && record.configuration.id() == record.header.configuration
                && hash("RLD-BATCH", self.disk.currency, &record.batch) == record.header.batch,
            "history record native identity"
        );
        Ok(Some((Arc::new(record), stored.storage_snapshot.0)))
    }
    pub fn iter(&self) -> Iter {
        self.range(0, self.len)
    }
    pub fn after(&self, sequence: u64) -> Iter {
        self.range(sequence, self.len)
    }
    /// Capture an immutable finite observation; never read later live appends.
    pub fn range(&self, after: u64, through: u64) -> Iter {
        Iter {
            history: self.clone(),
            next: after.checked_add(1),
            last: through.min(self.len),
            failed: false,
        }
    }
}
pub struct Iter {
    history: History,
    next: Option<u64>,
    last: u64,
    failed: bool,
}
impl Iterator for Iter {
    type Item = Result<Arc<Committed>>;
    fn next(&mut self) -> Option<Self::Item> {
        let sequence = self.next?;
        if self.failed || sequence > self.last {
            return None;
        }
        self.next = sequence.checked_add(1);
        let result = self
            .history
            .at(sequence)
            .and_then(|v| v.context("retained history gap"));
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}
