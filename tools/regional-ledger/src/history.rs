//! Immutable, content-addressed native storage. A page digest is not value
//! authority: reconstruct the exact journal, then execute native replay.
//! Exact predecessor prefixes are shared on disk, never treated as authority.
//! Reconstruction preserves the bounded logical ledger limits.
use crate::{
    storage::{read_bytes, safe_dir, Event, Journal},
    *,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub const FORMAT: &str = "RLD-NATIVE-HISTORY-MANIFEST-V2";
pub const SEGMENTED_FORMAT: &str = "RLD-NATIVE-HISTORY-PAGED-EVENTS-V1";
const OBJECT: &str = "RLD-NATIVE-HISTORY-OBJECT-V2";
pub const PAGE_EVENTS: usize = 16;
pub const MAX_FILES: usize = 4096;
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub hash: Hash,
    pub bytes: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub bootstrap: Bootstrap,
    pub region: Hash,
    pub journal: Hash,
    pub journal_bytes: usize,
    pub snapshots: Vec<Reference>,
    pub pages: Vec<Reference>,
    pub incident_ids: BTreeSet<Hash>,
    pub epochs: Vec<Reference>,
    pub contacts: Vec<(Hash, Reference)>,
}
impl Manifest {
    pub fn head(&self) -> Result<Hash> {
        id("native-history-head", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    first_event: usize,
    height_before: u64,
    height_after: u64,
    previous: Hash,
    events: Vec<Event>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPrefix {
    predecessor: Reference,
    prefix_blocks: usize,
    // Only the new blocks are stored here. The certificate still commits to
    // the complete native history reconstructed from the exact predecessor.
    suffix: Box<Snapshot>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Payload {
    Snapshot(Box<Snapshot>),
    SnapshotPrefix(SnapshotPrefix),
    Events(Page),
    Epoch(Box<epoch::Transition>),
    Contact(Box<contact::Record>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    format: String,
    currency: Hash,
    region: Hash,
    payload: Payload,
}
fn err(e: std::io::Error) -> String {
    e.to_string()
}
fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let raw = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    require(raw.len() <= MAX_BYTES, "native history object byte bound")?;
    Ok(raw)
}
fn decode<T: Serialize + serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    require(
        canonical(&value)? == raw,
        "noncanonical native history bytes",
    )?;
    Ok(value)
}
fn validate_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(err)?;
    require(
        meta.is_file() && !meta.file_type().is_symlink(),
        "unsafe native history file",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "native history file ownership, links or permissions",
        )?;
    }
    Ok(())
}
fn archive_usage(dir: &Path) -> Result<(usize, u64)> {
    safe_dir(dir)?;
    let mut count = 0usize;
    let mut bytes = 0u64;
    for entry in fs::read_dir(dir).map_err(err)? {
        let path = entry.map_err(err)?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("history filename encoding")?;
        require(
            name.len() == 69
                && name.ends_with(".json")
                && name.as_bytes()[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "unexpected native history archive entry",
        )?;
        validate_file(&path)?;
        let length = fs::symlink_metadata(&path).map_err(err)?.len();
        require(
            length <= MAX_BYTES as u64,
            "archived native history object byte bound",
        )?;
        count = count.checked_add(1).ok_or("history file count overflow")?;
        bytes = bytes
            .checked_add(length)
            .ok_or("history byte count overflow")?;
        require(
            count <= MAX_FILES && bytes <= MAX_ARCHIVE_BYTES,
            "native history archive capacity",
        )?;
    }
    Ok((count, bytes))
}
fn retained_file(path: &Path) -> Result<File> {
    validate_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(err)?;
    let meta = file.metadata().map_err(err)?;
    require(
        meta.is_file() && meta.len() <= MAX_BYTES as u64,
        "native history opened file type or bound",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0,
            "native history opened ownership, links or permissions",
        )?;
    }
    Ok(file)
}
fn retained_read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    retained_file(path)?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    require(
        bytes.len() <= MAX_BYTES,
        "native history file grew beyond bound",
    )?;
    Ok(bytes)
}
fn reference(object: &Object) -> Result<(Reference, Vec<u8>)> {
    let raw = canonical(object)?;
    Ok((
        Reference {
            hash: id("native-history-object", object)?,
            bytes: raw.len(),
        },
        raw,
    ))
}
/// Encode objects first. Unreferenced residue is retained, never adopted, deleted
/// or overwritten to get a passing head. An existing object must match exactly
/// and is fsynced again before any manifest acknowledgment.
#[cfg(test)]
pub(crate) fn prepare(dir: &Path, journal: &Journal) -> Result<Vec<u8>> {
    Ok(prepare_journal(dir, journal)?.1)
}
pub(crate) fn prepare_journal(dir: &Path, journal: &Journal) -> Result<(Journal, Vec<u8>)> {
    let segmented = segmented_journal(journal)?;
    require(
        segmented || journal.event_prefix.is_empty(),
        "legacy history cannot adopt event pages",
    )?;
    let mut retained = journal.clone();
    let archive = dir.join("history");
    let (mut files, mut total) = archive_usage(&archive)?;
    let currency = journal.bootstrap.currency.id()?;
    let mut objects: BTreeMap<Hash, Vec<u8>> = BTreeMap::new();
    let mut retain = |payload| -> Result<Reference> {
        let object = Object {
            format: OBJECT.into(),
            currency,
            region: journal.region,
            payload,
        };
        let (reference, raw) = reference(&object)?;
        if let Some(old) = objects.insert(reference.hash, raw.clone()) {
            require(old == raw, "native history hash collision")?;
        }
        Ok(reference)
    };
    let mut manifest = Manifest {
        format: if segmented { SEGMENTED_FORMAT } else { FORMAT }.into(),
        bootstrap: journal.bootstrap.clone(),
        region: journal.region,
        journal: Hash::ZERO,
        journal_bytes: 0,
        snapshots: vec![],
        pages: vec![],
        incident_ids: journal.incident_ids.clone(),
        epochs: vec![],
        contacts: vec![],
    };
    let mut predecessors: BTreeMap<Hash, (usize, Reference)> = BTreeMap::new();
    for (index, snapshot) in journal.evidence.snapshots.iter().enumerate() {
        let prefix = snapshot.statement.previous.and_then(|ident| {
            predecessors.get(&ident).filter(|(i, _)| {
                let old = &journal.evidence.snapshots[*i];
                snapshot.base.is_none()
                    && old.base.is_none()
                    && old.statement.currency == snapshot.statement.currency
                    && old.statement.region == snapshot.statement.region
                    && old.blocks.len() < snapshot.blocks.len()
                    && snapshot.blocks.starts_with(&old.blocks)
            })
        });
        let payload = match prefix {
            Some((i, reference)) => {
                let prefix_blocks = journal.evidence.snapshots[*i].blocks.len();
                let mut suffix = snapshot.clone();
                suffix.blocks = snapshot.blocks[prefix_blocks..].to_vec();
                Payload::SnapshotPrefix(SnapshotPrefix {
                    predecessor: reference.clone(),
                    prefix_blocks,
                    suffix: Box::new(suffix),
                })
            }
            None => Payload::Snapshot(Box::new(snapshot.clone())),
        };
        let r = retain(payload)?;
        // Native evidence permits exact repeats and authenticated equivalent
        // BFT quorum encodings. Retain every listed proof, using the earliest
        // exact checkpoint object as the deterministic prefix carrier.
        predecessors
            .entry(snapshot.statement.id()?)
            .or_insert((index, r.clone()));
        manifest.snapshots.push(r);
    }
    let mut height = 0u64;
    let mut previous = Hash::ZERO;
    let mut first_event = 0usize;
    if segmented {
        // Read complete preceding pages in order, retaining only one decoded
        // page. References and hashes are never a shortcut around replay.
        for r in &journal.event_prefix {
            let page = event_page(dir, &manifest, r, first_event, height, previous, true)?;
            height = page.height_after;
            first_event = first_event
                .checked_add(page.events.len())
                .ok_or("history event offset overflow")?;
            previous = r.hash;
            manifest.pages.push(r.clone());
        }
        retained.events.clear();
    }
    for events in journal.events.chunks(PAGE_EVENTS) {
        let before = height;
        for event in events {
            if let Event::Block(block) = event {
                require(
                    block.header.height
                        == height.checked_add(1).ok_or("history height overflow")?,
                    "native history page height sequence",
                )?;
                height = block.header.height;
            }
        }
        let page = Page {
            first_event,
            height_before: before,
            height_after: height,
            previous,
            events: events.to_vec(),
        };
        let reference = retain(Payload::Events(page))?;
        first_event = first_event
            .checked_add(events.len())
            .ok_or("history event offset overflow")?;
        previous = reference.hash;
        if segmented {
            if events.len() == PAGE_EVENTS {
                retained.event_prefix.push(reference.clone());
            } else {
                retained.events.extend_from_slice(events);
            }
        }
        manifest.pages.push(reference);
    }
    for proof in &journal.epoch_proofs {
        manifest
            .epochs
            .push(retain(Payload::Epoch(Box::new(proof.clone())))?);
    }
    for (key, record) in &journal.contact_records {
        manifest
            .contacts
            .push((*key, retain(Payload::Contact(Box::new(record.clone())))?));
    }
    manifest.journal = id("journal", &retained)?;
    manifest.journal_bytes = canonical(&retained)?.len();
    let raw = canonical(&manifest)?;
    // Preflight all archive admission before writing any new object. Actual I/O
    // failure may still leave unaccepted residue; no manifest is published then.
    for (hash, bytes) in &objects {
        let path = archive.join(format!("{}.json", hash.to_hex()));
        if fs::symlink_metadata(&path).is_ok() {
            require(
                retained_read(&path)? == *bytes,
                "retained native history bytes differ",
            )?;
        } else {
            files = files.checked_add(1).ok_or("history count overflow")?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("history bytes overflow")?;
            require(
                files <= MAX_FILES && total <= MAX_ARCHIVE_BYTES,
                "native history archive capacity",
            )?;
        }
    }
    for (hash, bytes) in objects {
        let path = archive.join(format!("{}.json", hash.to_hex()));
        if fs::symlink_metadata(&path).is_ok() {
            require(
                retained_read(&path)? == bytes,
                "retained native history bytes differ",
            )?;
            retained_file(&path)?.sync_all().map_err(err)?;
        } else {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(&path).map_err(err)?;
            file.write_all(&bytes).map_err(err)?;
            file.sync_all().map_err(err)?;
        }
    }
    // A repeated commit also durably retains every referenced old page.
    // Admission still counts old partial tails and all unaccepted residue.
    for r in &journal.event_prefix {
        retained_file(&archive.join(format!("{}.json", r.hash.to_hex())))?
            .sync_all()
            .map_err(err)?;
    }
    File::open(&archive).map_err(err)?.sync_all().map_err(err)?;
    Ok((retained, raw))
}
fn object(dir: &Path, m: &Manifest, reference: &Reference) -> Result<Payload> {
    require(
        reference.bytes > 0 && reference.bytes <= MAX_BYTES,
        "native history reference byte bound",
    )?;
    let raw = retained_read(
        &dir.join("history")
            .join(format!("{}.json", reference.hash.to_hex())),
    )?;
    require(
        raw.len() == reference.bytes,
        "native history reference size mismatch",
    )?;
    let object: Object = decode(&raw)?;
    require(
        object.format == OBJECT
            && object.currency == m.bootstrap.currency.id()?
            && object.region == m.region
            && id("native-history-object", &object)? == reference.hash,
        "native history object scope or digest mismatch",
    )?;
    Ok(object.payload)
}
fn segmented_journal(journal: &Journal) -> Result<bool> {
    let region = journal
        .bootstrap
        .admissions
        .iter()
        .find(|a| a.id().ok() == Some(journal.region))
        .ok_or("history region missing from bootstrap")?;
    Ok(region.rules == crate::segmented::RULES)
}
fn event_page(
    dir: &Path,
    m: &Manifest,
    reference: &Reference,
    first: usize,
    height: u64,
    previous: Hash,
    full: bool,
) -> Result<Page> {
    let page = match object(dir, m, reference)? {
        Payload::Events(page) => page,
        _ => return Err("native history event reference type".into()),
    };
    require(
        page.first_event == first
            && page.height_before == height
            && page.previous == previous
            && !page.events.is_empty()
            && page.events.len() <= PAGE_EVENTS
            && (!full || page.events.len() == PAGE_EVENTS),
        "native history page order, parent or range",
    )?;
    let mut end = height;
    for event in &page.events {
        if let Event::Block(block) = event {
            require(
                block.header.height == end.checked_add(1).ok_or("history height overflow")?,
                "native history reconstructed height sequence",
            )?;
            end = block.header.height;
        }
    }
    require(
        page.height_after == end,
        "native history page ending height",
    )?;
    Ok(page)
}
/// Owned fallible events retain at most one immutable disk page plus the
/// separately bounded unsealed tail. Each lookup authenticates exact bytes.
pub(crate) struct Events<'a> {
    dir: Option<&'a Path>,
    journal: &'a Journal,
    scope: Manifest,
    page_index: usize,
    first: usize,
    height: u64,
    previous: Hash,
    current: std::vec::IntoIter<Event>,
    tail: bool,
    failed: bool,
}
pub(crate) fn events<'a>(dir: Option<&'a Path>, journal: &'a Journal) -> Result<Events<'a>> {
    require(
        journal.event_prefix.is_empty() || (dir.is_some() && segmented_journal(journal)?),
        "paged event history requires explicit profile and native disk context",
    )?;
    require(
        journal.event_prefix.len() <= MAX_FILES,
        "native event page count bound",
    )?;
    Ok(Events {
        dir,
        journal,
        scope: Manifest {
            format: SEGMENTED_FORMAT.into(),
            bootstrap: journal.bootstrap.clone(),
            region: journal.region,
            journal: Hash::ZERO,
            journal_bytes: 0,
            snapshots: vec![],
            pages: vec![],
            incident_ids: BTreeSet::new(),
            epochs: vec![],
            contacts: vec![],
        },
        page_index: 0,
        first: 0,
        height: 0,
        previous: Hash::ZERO,
        current: Vec::new().into_iter(),
        tail: false,
        failed: false,
    })
}
impl Iterator for Events<'_> {
    type Item = Result<Event>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            if let Some(event) = self.current.next() {
                return Some(Ok(event));
            }
            if let Some(r) = self.journal.event_prefix.get(self.page_index) {
                let result = event_page(
                    self.dir.expect("checked native disk context"),
                    &self.scope,
                    r,
                    self.first,
                    self.height,
                    self.previous,
                    true,
                );
                match result {
                    Ok(page) => {
                        self.first += page.events.len();
                        self.height = page.height_after;
                        self.previous = r.hash;
                        self.page_index += 1;
                        self.current = page.events.into_iter();
                    }
                    Err(e) => {
                        self.failed = true;
                        return Some(Err(e));
                    }
                }
            } else if !self.tail {
                self.tail = true;
                self.current = self.journal.events.clone().into_iter();
            } else {
                return None;
            }
        }
    }
}
pub fn manifest(dir: &Path) -> Result<Manifest> {
    safe_dir(dir)?;
    let m: Manifest = decode(&read_bytes(&dir.join("journal.json"), MAX_BYTES)?)?;
    require(
        (m.format == FORMAT || m.format == SEGMENTED_FORMAT)
            && m.journal_bytes > 0
            && m.journal_bytes <= MAX_BYTES,
        "native history manifest format or logical bound",
    )?;
    require(
        m.snapshots.len() <= MAX_SNAPSHOTS
            && m.epochs.len() <= epoch::MAX_EPOCHS
            && m.contacts.len() <= contact::MAX_CONTACTS
            && m.incident_ids.len() <= conflict::MAX_INCIDENTS
            && m.pages.len()
                <= if m.format == SEGMENTED_FORMAT {
                    MAX_FILES
                } else {
                    (MAX_BLOCKS + MAX_SNAPSHOTS + epoch::MAX_EPOCHS).div_ceil(PAGE_EVENTS)
                },
        "native history manifest reference bounds",
    )?;
    archive_usage(&dir.join("history"))?;
    Ok(m)
}
/// Reconstruct bytes; caller must still replay native rules. No manifest or
/// content hash replaces currency, finality, owner or permanent-import checks.
pub fn read_journal(dir: &Path) -> Result<Journal> {
    let m = manifest(dir)?;
    let mut journal = Journal {
        bootstrap: m.bootstrap.clone(),
        region: m.region,
        evidence: Evidence::default(),
        events: vec![],
        event_prefix: vec![],
        incident_ids: m.incident_ids.clone(),
        epoch_proofs: vec![],
        contact_records: BTreeMap::new(),
    };
    let segmented = m.format == SEGMENTED_FORMAT;
    require(
        segmented == segmented_journal(&journal)?,
        "history storage profile differs; no automatic format conversion",
    )?;
    // Cumulative serialized payload admission bounds allocation before decoding
    // objects. The immutable archive itself may contain old and orphan objects.
    let refs = m
        .snapshots
        .iter()
        .chain(m.pages.iter().filter(|_| !segmented))
        .chain(m.epochs.iter())
        .chain(m.contacts.iter().map(|(_, r)| r));
    let mut referenced_bytes = 0usize;
    for r in refs {
        referenced_bytes = referenced_bytes
            .checked_add(r.bytes)
            .ok_or("history reference total overflow")?;
        // Object wrappers add bounded metadata above the original logical bytes.
        require(
            referenced_bytes <= MAX_BYTES + MAX_FILES * 512,
            "native history reconstruction byte bound",
        )?;
    }
    let mut predecessors: BTreeMap<Hash, usize> = BTreeMap::new();
    let mut expanded_bytes = 0usize;
    for (index, r) in m.snapshots.iter().enumerate() {
        let snapshot = match object(dir, &m, r)? {
            Payload::Snapshot(s) => *s,
            Payload::SnapshotPrefix(p) => {
                // Only a preceding, directly listed object may supply a prefix.
                // No recursive traversal, orphan adoption or unchecked cache.
                let i = *predecessors
                    .get(&p.predecessor.hash)
                    .ok_or("native history prefix missing preceding object")?;
                require(
                    m.snapshots[i].bytes == p.predecessor.bytes,
                    "native history prefix reference size",
                )?;
                let old = &journal.evidence.snapshots[i];
                let mut suffix = *p.suffix;
                let count = p
                    .prefix_blocks
                    .checked_add(suffix.blocks.len())
                    .ok_or("native history prefix block overflow")?;
                require(
                    p.prefix_blocks > 0
                        && p.prefix_blocks == old.blocks.len()
                        && old.statement.height == p.prefix_blocks as u64
                        && !suffix.blocks.is_empty()
                        && count <= MAX_BLOCKS
                        && suffix.statement.height == count as u64
                        && suffix.statement.previous == Some(old.statement.id()?)
                        && suffix.statement.currency == old.statement.currency
                        && suffix.statement.region == old.statement.region,
                    "native history prefix identity, predecessor or block range",
                )?;
                // Bound expansion before cloning the shared blocks. The full
                // canonical snapshot admission below also bounds all retained
                // expanded snapshots by the declared logical journal size.
                let prefix_bytes = canonical(&old.blocks)?.len();
                let suffix_bytes = canonical(&suffix)?.len();
                require(
                    prefix_bytes
                        .checked_add(suffix_bytes)
                        .is_some_and(|n| n <= MAX_BYTES + 2),
                    "native history prefix expansion byte bound",
                )?;
                let mut blocks = old.blocks.clone();
                blocks.append(&mut suffix.blocks);
                suffix.blocks = blocks;
                suffix
            }
            _ => return Err("native history snapshot reference type".into()),
        };
        expanded_bytes = expanded_bytes
            .checked_add(canonical(&snapshot)?.len())
            .ok_or("native history expanded snapshot total overflow")?;
        require(
            expanded_bytes <= m.journal_bytes,
            "native history expanded snapshot logical bound",
        )?;
        predecessors.entry(r.hash).or_insert(index);
        journal.evidence.snapshots.push(snapshot);
    }
    let mut height = 0u64;
    let mut previous = Hash::ZERO;
    let mut first_event = 0usize;
    for (i, r) in m.pages.iter().enumerate() {
        let page = event_page(
            dir,
            &m,
            r,
            first_event,
            height,
            previous,
            i + 1 < m.pages.len(),
        )?;
        height = page.height_after;
        first_event = first_event
            .checked_add(page.events.len())
            .ok_or("history event offset overflow")?;
        if segmented && page.events.len() == PAGE_EVENTS {
            journal.event_prefix.push(r.clone());
        } else {
            journal.events.extend(page.events);
        }
        previous = r.hash;
    }
    for r in &m.epochs {
        match object(dir, &m, r)? {
            Payload::Epoch(p) => journal.epoch_proofs.push(*p),
            _ => return Err("native history epoch reference type".into()),
        }
    }
    let mut previous_contact = None;
    for (key, r) in &m.contacts {
        require(
            previous_contact.is_none_or(|old| old < *key),
            "native history contact order",
        )?;
        match object(dir, &m, r)? {
            Payload::Contact(p) if p.message_id == *key => {
                journal.contact_records.insert(*key, *p);
            }
            _ => return Err("native history contact reference type or identity".into()),
        }
        previous_contact = Some(*key);
    }
    let raw = canonical(&journal)?;
    require(
        raw.len() == m.journal_bytes && id("journal", &journal)? == m.journal,
        "native history reconstructed journal commitment",
    )?;
    Ok(journal)
}
#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
