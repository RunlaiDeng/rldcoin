//! Complete private byte retention for the future ordinary BFT history/signer
//! integration. This storage layer grants NO native authority, signatures,
//! custody recovery, admission or ledger state. Its caller must authenticate
//! and execute every record from genesis, under its own native lock and rules.
//! Existing Store/Agent formats do not adopt this layer automatically.
use crate::{history, keystore, storage, *};
use serde::de::DeserializeOwned;
use std::{
    fs::{self, File, OpenOptions},
    marker::PhantomData,
    path::{Path, PathBuf},
};

const FORMAT: &str = "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1";
const MANIFEST: &str = "stream.json";
const PENDING: &str = "stream.next";
const COMMIT: &str = "stream.commit";
const OBJECTS: &str = "pages";
const PAGE: usize = history::PAGE_EVENTS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Purpose {
    Ledger,
    BftSigner(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    implementation: Hash,
    currency: Hash,
    region: Hash,
    admission: Hash,
    purpose: Purpose,
    origin: Hash,
}
impl Scope {
    /// Bind already native-verified trust. `origin` is caller-supplied storage
    /// context, never an independent latest witness or custody provenance.
    pub fn bind(trust: &Trust, region: Hash, purpose: Purpose, origin: Hash) -> Result<Self> {
        if let Purpose::BftSigner(key) = &purpose {
            validate_ed25519_public_key(key)?;
        }
        require(!origin.is_zero(), "stream origin context missing")?;
        Ok(Self {
            implementation: implementation()?,
            currency: trust.currency()?,
            region,
            admission: trust.region(region)?.id()?,
            purpose,
            origin,
        })
    }
    pub(crate) fn initial(&self) -> Result<Hash> {
        id("complete-stream-origin-v1", self)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest<T> {
    format: String,
    scope: Scope,
    pages: Vec<history::Reference>,
    tail: Vec<T>,
    count: u64,
    head: Hash,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page<T> {
    format: String,
    scope: Scope,
    first: u64,
    previous: Option<Hash>,
    records: Vec<T>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication<T> {
    expected_head: Hash,
    manifest: Manifest<T>,
    /// Full original records, not references to pages still in RAM. This is
    /// durable before any object publication or possible response release.
    pages: Vec<Page<T>>,
}

fn err(_: std::io::Error) -> String {
    "complete stream private storage operation failed".into()
}
fn bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(|_| "complete stream encoding")?;
    require(
        raw.len() <= MAX_BYTES,
        "complete stream object byte capacity",
    )?;
    Ok(raw)
}
fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    let value = serde_json::from_slice(raw).map_err(|_| "complete stream typed encoding")?;
    require(bytes(&value)? == raw, "complete stream noncanonical bytes")?;
    Ok(value)
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(err(e)),
    }
}
fn private_dir(path: &Path) -> Result<()> {
    storage::safe_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(path).map_err(err)?;
        require(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "complete stream directory ownership or permissions",
        )?;
    }
    Ok(())
}
fn make_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(err)?;
    File::open(path.parent().ok_or("stream parent missing")?)
        .map_err(err)?
        .sync_all()
        .map_err(err)
}
fn lock(dir: &Path) -> Result<File> {
    keystore::private_read(&dir.join("LOCK"), 0)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(dir.join("LOCK")).map_err(err)?;
    file.try_lock()
        .map_err(|_| "complete stream already locked")?;
    Ok(file)
}
fn page_name(hash: Hash) -> String {
    format!("{}.json", hash.to_hex())
}
fn usage(dir: &Path) -> Result<(usize, u64)> {
    private_dir(dir)?;
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in fs::read_dir(dir).map_err(err)? {
        let path = entry.map_err(err)?.path();
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("stream filename")?;
        require(
            name.len() == 69
                && name.ends_with(".json")
                && name.as_bytes()[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "unexpected complete stream page filename",
        )?;
        // Read retained orphans too: unsafe/oversized residue cannot disappear
        // behind an unreferenced object or a passing manifest digest.
        let length = keystore::private_read(&path, MAX_BYTES)?.len() as u64;
        count = count.checked_add(1).ok_or("stream file count overflow")?;
        total = total
            .checked_add(length)
            .ok_or("stream byte count overflow")?;
        require(
            count <= history::MAX_FILES && total <= history::MAX_ARCHIVE_BYTES,
            "complete stream archive capacity",
        )?;
    }
    Ok((count, total))
}
fn root_inventory(dir: &Path) -> Result<()> {
    private_dir(dir)?;
    for entry in fs::read_dir(dir).map_err(err)? {
        let name = entry.map_err(err)?.file_name();
        require(
            matches!(
                name.to_str(),
                Some("LOCK" | MANIFEST | PENDING | COMMIT | OBJECTS)
            ),
            "unexpected complete stream root entry",
        )?;
    }
    Ok(())
}
pub(crate) fn next_head<T: Serialize>(previous: Hash, index: u64, record: &T) -> Result<Hash> {
    id("complete-stream-record-v1", &(previous, index, record))
}

/// Owns a private OS lock. A returned storage head is integrity metadata only.
/// This API neither verifies signatures nor initializes a native execution state.
pub struct Stream<T> {
    dir: PathBuf,
    _lock: File,
    manifest: Manifest<T>,
    healthy: bool,
    _type: PhantomData<T>,
    #[cfg(test)]
    interruption: Option<Boundary>,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Boundary {
    Pending,
    Pages,
    Committed,
}
impl<T: Clone + Serialize + DeserializeOwned> Stream<T> {
    pub fn create(dir: &Path, scope: Scope) -> Result<Self> {
        private_dir(dir.parent().ok_or("stream parent missing")?)?;
        require(!exists(dir)?, "stream creation requires absent directory")?;
        make_dir(dir)?;
        keystore::private_create(&dir.join("LOCK"), b"")?;
        let guard = lock(dir)?;
        make_dir(&dir.join(OBJECTS))?;
        let manifest = Manifest {
            format: FORMAT.into(),
            head: scope.initial()?,
            scope,
            pages: vec![],
            tail: vec![],
            count: 0,
        };
        keystore::private_create(&dir.join(MANIFEST), &bytes(&manifest)?)?;
        Ok(Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            healthy: true,
            _type: PhantomData,
            #[cfg(test)]
            interruption: None,
        })
    }
    pub fn open(dir: &Path, scope: &Scope, expected_head: Hash) -> Result<Self> {
        private_dir(dir)?;
        let guard = lock(dir)?;
        require(
            !exists(&dir.join(PENDING))? && !exists(&dir.join(COMMIT))?,
            "incomplete complete stream publication; retain residue",
        )?;
        let manifest: Manifest<T> =
            decode(&keystore::private_read(&dir.join(MANIFEST), MAX_BYTES)?)?;
        require(
            manifest.format == FORMAT && manifest.scope == *scope,
            "complete stream format/scope; no conversion",
        )?;
        let stream = Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            healthy: true,
            _type: PhantomData,
            #[cfg(test)]
            interruption: None,
        };
        stream.visit(expected_head, |_| Ok(()))?;
        Ok(stream)
    }
    /// Inspect complete ordered records after structural verification. The
    /// supplied consumer must start at native genesis and stage semantic state;
    /// do not publish any derived authority until this whole call succeeds.
    pub fn visit(
        &self,
        expected_head: Hash,
        mut consumer: impl FnMut(&T) -> Result<()>,
    ) -> Result<u64> {
        require(
            self.healthy && !exists(&self.dir.join(PENDING))? && !exists(&self.dir.join(COMMIT))?,
            "incomplete complete stream publication; retain residue",
        )?;
        root_inventory(&self.dir)?;
        require(
            self.manifest.pages.len() <= history::MAX_FILES && self.manifest.tail.len() < PAGE,
            "complete stream page/tail capacity",
        )?;
        let (files, retained) = usage(&self.dir.join(OBJECTS))?;
        let manifest_bytes = bytes(&self.manifest)?.len() as u64;
        require(
            files
                .checked_add(2)
                .is_some_and(|n| n <= history::MAX_FILES)
                && retained
                    .checked_add(manifest_bytes)
                    .is_some_and(|n| n <= history::MAX_ARCHIVE_BYTES),
            "complete stream total archive capacity",
        )?;
        let mut index = 0u64;
        let mut head = self.manifest.scope.initial()?;
        let mut previous = None;
        for reference in &self.manifest.pages {
            require(
                reference.bytes > 0 && reference.bytes <= MAX_BYTES,
                "complete stream page size",
            )?;
            let raw = keystore::private_read(
                &self.dir.join(OBJECTS).join(page_name(reference.hash)),
                MAX_BYTES,
            )?;
            require(
                raw.len() == reference.bytes
                    && Hash(Sha256::digest(&*raw).into()) == reference.hash,
                "complete stream page digest/length",
            )?;
            let page: Page<T> = decode(&raw)?;
            require(
                page.format == FORMAT
                    && page.scope == self.manifest.scope
                    && page.first == index
                    && page.previous == previous
                    && page.records.len() == PAGE,
                "complete stream page order/domain/predecessor",
            )?;
            for record in &page.records {
                consumer(record)?;
                head = next_head(head, index, record)?;
                index = index.checked_add(1).ok_or("stream record count overflow")?;
            }
            previous = Some(reference.hash);
        }
        for record in &self.manifest.tail {
            consumer(record)?;
            head = next_head(head, index, record)?;
            index = index.checked_add(1).ok_or("stream record count overflow")?;
        }
        require(
            index == self.manifest.count && head == self.manifest.head && head == expected_head,
            "complete stream exact latest head/count",
        )?;
        Ok(index)
    }
    /// A native consumer must bind the complete stream domain before replay.
    /// Equality is storage context only, never signature/admission authority.
    pub(crate) fn require_scope(&self, expected: &Scope) -> Result<()> {
        require(
            self.manifest.scope == *expected,
            "complete stream native consumer scope",
        )
    }
    /// Unpinned integrity observation only, never independent latest authority.
    pub(crate) fn observe_head(dir: &Path, scope: &Scope) -> Result<Hash> {
        let manifest: Manifest<T> =
            decode(&keystore::private_read(&dir.join(MANIFEST), MAX_BYTES)?)?;
        require(
            manifest.format == FORMAT && manifest.scope == *scope,
            "complete stream observed scope",
        )?;
        Ok(manifest.head)
    }
    pub(crate) fn records(&self, expected: Hash) -> Result<Records<'_, T>> {
        self.visit(expected, |_| Ok(()))?;
        Ok(Records {
            stream: self,
            page: 0,
            index: 0,
            previous: None,
            tail: false,
            failed: false,
            ready: std::collections::VecDeque::new(),
        })
    }
    pub fn storage_head(&self) -> Hash {
        self.manifest.head
    }
    pub fn record_count(&self) -> u64 {
        self.manifest.count
    }

    /// Append exact complete records only after the native caller has validated
    /// their meaning. No automatic recovery or authorizing callback is supplied.
    /// All capacity checks precede disk writes; I/O failure retains residue.
    pub fn append(&mut self, records: &[T], expected_head: Hash) -> Result<Hash> {
        self.append_accounted(records, expected_head, 0, 0)
    }
    /// The native store includes all separately retained metadata/incident/queue
    /// files in this same unchanged archive ceiling before any stream write.
    pub(crate) fn append_accounted(
        &mut self,
        records: &[T],
        expected_head: Hash,
        external_files: usize,
        external_bytes: u64,
    ) -> Result<Hash> {
        self.visit(expected_head, |_| Ok(()))?;
        require(
            !records.is_empty() && records.len() <= PAGE,
            "complete stream append batch bound",
        )?;
        require(
            bytes(&records)?
                .len()
                .checked_add(bytes(&self.manifest.tail)?.len())
                .is_some_and(|n| n <= MAX_BYTES),
            "complete stream staged record byte capacity",
        )?;
        let mut proposed = self.manifest.clone();
        let mut objects = Vec::new();
        for record in records {
            proposed.head = next_head(proposed.head, proposed.count, record)?;
            proposed.count = proposed
                .count
                .checked_add(1)
                .ok_or("stream record count overflow")?;
            proposed.tail.push(record.clone());
            if proposed.tail.len() == PAGE {
                let page = Page {
                    format: FORMAT.into(),
                    scope: proposed.scope.clone(),
                    first: proposed
                        .count
                        .checked_sub(PAGE as u64)
                        .ok_or("stream page offset")?,
                    previous: proposed.pages.last().map(|r| r.hash),
                    records: std::mem::take(&mut proposed.tail),
                };
                let raw = bytes(&page)?;
                let hash = Hash(Sha256::digest(&raw).into());
                proposed.pages.push(history::Reference {
                    hash,
                    bytes: raw.len(),
                });
                objects.push((hash, raw));
            }
        }
        let raw = bytes(&proposed)?;
        let publication = Publication {
            expected_head: self.manifest.head,
            manifest: proposed.clone(),
            pages: objects
                .iter()
                .map(|(_, raw)| decode(raw))
                .collect::<Result<Vec<Page<T>>>>()?,
        };
        let pending_raw = bytes(&publication)?;
        let archive = self.dir.join(OBJECTS);
        let (mut count, mut total) = usage(&archive)?;
        // Include current manifest, complete pending payload, commit manifest
        // and the retained LOCK;
        // failed publication must also fit. Old pages/orphans always count.
        total = total
            .checked_add(bytes(&self.manifest)?.len() as u64)
            .and_then(|n| n.checked_add(pending_raw.len() as u64))
            .and_then(|n| n.checked_add(raw.len() as u64))
            .ok_or("stream manifest byte overflow")?;
        count = count
            .checked_add(4)
            .ok_or("stream archive count overflow")?;
        for (hash, content) in &objects {
            let path = archive.join(page_name(*hash));
            if exists(&path)? {
                require(
                    &*keystore::private_read(&path, MAX_BYTES)? == content,
                    "complete stream immutable object differs",
                )?;
            } else {
                count = count
                    .checked_add(1)
                    .ok_or("stream archive count overflow")?;
                total = total
                    .checked_add(content.len() as u64)
                    .ok_or("stream archive byte overflow")?;
            }
        }
        require(
            count
                .checked_add(external_files)
                .is_some_and(|n| n <= history::MAX_FILES)
                && total
                    .checked_add(external_bytes)
                    .is_some_and(|n| n <= history::MAX_ARCHIVE_BYTES),
            "complete stream total archive capacity",
        )?;
        let outcome = (|| {
            // Marker precedes page publication: every interrupted write is a
            // refusing scope, even if the old manifest still matches its head.
            keystore::private_create(&self.dir.join(PENDING), &pending_raw)?;
            #[cfg(test)]
            if self.interruption == Some(Boundary::Pending) {
                return Err("injected after retained pending publication".into());
            }
            for (hash, content) in &objects {
                let path = archive.join(page_name(*hash));
                if exists(&path)? {
                    require(
                        &*keystore::private_read(&path, MAX_BYTES)? == content,
                        "complete stream immutable object differs",
                    )?;
                    File::open(path).map_err(err)?.sync_all().map_err(err)?;
                    File::open(&archive).map_err(err)?.sync_all().map_err(err)?;
                } else {
                    keystore::private_create(&path, content)?;
                }
            }
            #[cfg(test)]
            if self.interruption == Some(Boundary::Pages) {
                return Err("injected after retained page publication".into());
            }
            keystore::private_create(&self.dir.join(COMMIT), &raw)?;
            fs::rename(self.dir.join(COMMIT), self.dir.join(MANIFEST)).map_err(err)?;
            File::open(&self.dir)
                .map_err(err)?
                .sync_all()
                .map_err(err)?;
            #[cfg(test)]
            if self.interruption == Some(Boundary::Committed) {
                return Err("injected after retained manifest publication".into());
            }
            // Every unique original byte is now durable in the exact page/tail.
            // Only this completed redundant wrapper is removed. Any failure
            // before completion keeps its marker/payload and refuses reopen.
            fs::remove_file(self.dir.join(PENDING)).map_err(err)?;
            File::open(&self.dir).map_err(err)?.sync_all().map_err(err)
        })();
        if outcome.is_err() {
            self.healthy = false;
        }
        outcome?;
        self.manifest = proposed;
        Ok(self.manifest.head)
    }
}

/// One fully checked complete page at a time, after full structural head check.
/// Native consumers must still execute the whole history before publishing.
pub(crate) struct Records<'a, T> {
    stream: &'a Stream<T>,
    page: usize,
    index: u64,
    previous: Option<Hash>,
    tail: bool,
    failed: bool,
    ready: std::collections::VecDeque<T>,
}
impl<T: Clone + Serialize + DeserializeOwned> Iterator for Records<'_, T> {
    type Item = Result<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.ready.is_empty() {
            let loaded = (|| -> Result<()> {
                if let Some(reference) = self.stream.manifest.pages.get(self.page) {
                    let raw = keystore::private_read(
                        &self
                            .stream
                            .dir
                            .join(OBJECTS)
                            .join(page_name(reference.hash)),
                        MAX_BYTES,
                    )?;
                    require(
                        raw.len() == reference.bytes
                            && Hash(Sha256::digest(&raw).into()) == reference.hash,
                        "complete record cursor page digest/length",
                    )?;
                    let page: Page<T> = decode(&raw)?;
                    require(
                        page.format == FORMAT
                            && page.scope == self.stream.manifest.scope
                            && page.first == self.index
                            && page.previous == self.previous
                            && page.records.len() == PAGE,
                        "complete record cursor order/domain",
                    )?;
                    self.ready = page.records.into();
                    self.previous = Some(reference.hash);
                    self.page += 1;
                } else if !self.tail {
                    self.ready = self.stream.manifest.tail.clone().into();
                    self.tail = true;
                }
                Ok(())
            })();
            if let Err(e) = loaded {
                self.failed = true;
                return Some(Err(e));
            }
        }
        self.ready.pop_front().map(|record| {
            self.index += 1;
            Ok(record)
        })
    }
}

#[path = "retained_recovery.rs"]
mod recovery;

#[cfg(test)]
impl<T> Stream<T> {
    pub(crate) fn interrupt_at(&mut self, boundary: u8) {
        self.interruption = Some(match boundary {
            0 => Boundary::Pending,
            1 => Boundary::Pages,
            2 => Boundary::Committed,
            _ => panic!("unknown fixture interruption boundary"),
        });
    }
}

#[cfg(test)]
pub(crate) use recovery::rewrite_last_pending_for_fixture;

#[cfg(test)]
mod tests;
