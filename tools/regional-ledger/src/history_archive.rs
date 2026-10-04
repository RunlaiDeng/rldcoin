//! Private bounded ledger images. Exact storage commitments are integrity checks,
//! never balance, signer, wallet or independent latest-state authority.
use crate::{
    storage::{safe_dir, Store},
    *,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
};

pub const FORMAT: &str = "RLD-NATIVE-HISTORY-ARCHIVE-V1";
const MARKER: &[u8] = b"RLD-NATIVE-HISTORY-RESTORING-V1\n";
const SEALING: &[u8] = b"RLD-NATIVE-HISTORY-ARCHIVING-V1\n";
const MAX_FILES: usize = history::MAX_FILES + 2 * conflict::MAX_INCIDENTS + 2;
const MAX_TOTAL: u64 =
    history::MAX_ARCHIVE_BYTES + (2 * conflict::MAX_INCIDENTS as u64 + 1) * MAX_BYTES as u64 + 32;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub bytes: u64,
    pub sha256: Hash,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub native_head: Hash,
    pub retained_bytes: u64,
    pub files: BTreeMap<String, Record>,
}
impl Archive {
    pub fn commitment(&self) -> Result<Hash> {
        id("native-history-archive", self)
    }
}
fn io(e: std::io::Error) -> String {
    e.to_string()
}
fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha256::digest(bytes).into())
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io(e)),
    }
}
fn canonical_path(path: &Path) -> Result<()> {
    require(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "archive path must be absolute without dot components",
    )
}
fn private_dir(path: &Path) -> Result<()> {
    safe_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::symlink_metadata(path).map_err(io)?;
        require(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o077 == 0,
            "archive directory ownership or permissions",
        )?;
    }
    Ok(())
}
fn file_metadata(meta: &fs::Metadata, private: bool) -> Result<()> {
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_BYTES as u64,
        "archive input type or byte bound",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.nlink() == 1
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & if private { 0o077 } else { 0o022 } == 0,
            "archive file ownership, links or permissions",
        )?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}
fn read(path: &Path, private: bool) -> Result<Vec<u8>> {
    file_metadata(&fs::symlink_metadata(path).map_err(io)?, private)?;
    let mut opt = OpenOptions::new();
    opt.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opt.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opt.open(path).map_err(io)?;
    file_metadata(&file.metadata().map_err(io)?, private)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    require(bytes.len() <= MAX_BYTES, "archive input grew beyond bound")?;
    Ok(bytes)
}
fn sync(dir: &Path) -> Result<()> {
    File::open(dir).map_err(io)?.sync_all().map_err(io)
}
fn new_file(path: &Path, bytes: &[u8]) -> Result<File> {
    require(bytes.len() <= MAX_BYTES, "archive output byte bound")?;
    let mut opt = OpenOptions::new();
    opt.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opt.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = opt.open(path).map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    Ok(file)
}
fn new_dir(path: &Path) -> Result<()> {
    let mut opt = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        opt.mode(0o700);
    }
    opt.create(path).map_err(io)?;
    sync(path.parent().ok_or("archive parent missing")?)
}
fn fresh(path: &Path, source: &Path) -> Result<()> {
    canonical_path(path)?;
    canonical_path(source)?;
    let parent = path.parent().ok_or("archive parent missing")?;
    safe_dir(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::symlink_metadata(parent).map_err(io)?;
        require(
            m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o022 == 0,
            "unsafe archive target parent",
        )?;
    }
    require(
        !path.starts_with(source) && !source.starts_with(path),
        "archive and native paths overlap",
    )?;
    require(
        !exists(path)?,
        "archive/restore destination already exists; retain it unchanged",
    )
}
fn object_name(name: &str) -> bool {
    name.len() == 69
        && name.ends_with(".json")
        && name.as_bytes()[..64]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn residue_name(name: &str) -> bool {
    name.strip_prefix("damaged-incident-")
        .and_then(|s| s.strip_suffix(".bin"))
        .is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn inventory(
    dir: &Path,
    strict: bool,
    controls: &[&str],
) -> Result<(BTreeMap<String, Record>, u64)> {
    safe_dir(dir)?;
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    let mut add = |name: String| -> Result<()> {
        let bytes = read(&dir.join(&name), strict)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("archive byte overflow")?;
        require(
            total <= MAX_TOTAL && files.len() < MAX_FILES,
            "archive combined capacity",
        )?;
        require(
            files
                .insert(
                    name,
                    Record {
                        bytes: bytes.len() as u64,
                        sha256: hash(&bytes),
                    },
                )
                .is_none(),
            "duplicate archive entry",
        )?;
        Ok(())
    };
    add("journal.json".into())?;
    add("INCIDENT_GUARD".into())?;
    for (kind, bound, max_bytes) in [
        ("history", history::MAX_FILES, history::MAX_ARCHIVE_BYTES),
        (
            "incidents",
            conflict::MAX_INCIDENTS,
            conflict::MAX_INCIDENTS as u64 * MAX_BYTES as u64,
        ),
    ] {
        let path = dir.join(kind);
        safe_dir(&path)?;
        if strict {
            private_dir(&path)?;
        }
        let mut count = 0usize;
        let mut bytes = 0u64;
        for entry in fs::read_dir(path).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("archive filename encoding")?;
            require(object_name(name), "unexpected archived native object name")?;
            count += 1;
            bytes = bytes
                .checked_add(fs::symlink_metadata(entry.path()).map_err(io)?.len())
                .ok_or("archive subdirectory byte overflow")?;
            require(
                count <= bound && bytes <= max_bytes,
                "archive native subdirectory capacity",
            )?;
            add(format!("{kind}/{name}"))?;
        }
    }
    let mut residue = 0;
    for entry in fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("archive root filename encoding")?;
        if name.starts_with("damaged-incident-") {
            require(
                residue_name(name),
                "unexpected damaged incident residue name",
            )?;
            residue += 1;
            require(
                residue <= conflict::MAX_INCIDENTS,
                "archive incident residue capacity",
            )?;
            add(name.into())?;
        } else if strict
            && !matches!(
                name,
                "journal.json" | "INCIDENT_GUARD" | "history" | "incidents"
            )
        {
            require(
                controls.contains(&name),
                "unexpected native archive image root entry",
            )?;
        }
    }
    Ok((files, total))
}
fn copy_image(
    source: &Path,
    target: &Path,
    index: &Archive,
    private: bool,
    mut copied: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    new_dir(&target.join("history"))?;
    new_dir(&target.join("incidents"))?;
    for (n, (name, record)) in index.files.iter().enumerate() {
        let bytes = read(&source.join(name), private)?;
        require(
            bytes.len() as u64 == record.bytes && hash(&bytes) == record.sha256,
            "archive bytes changed during copy",
        )?;
        new_file(&target.join(name), &bytes)?;
        copied(n + 1)?;
    }
    sync(&target.join("history"))?;
    sync(&target.join("incidents"))?;
    sync(target)
}
fn same_image(dir: &Path, index: &Archive, controls: &[&str]) -> Result<()> {
    let (files, total) = inventory(dir, true, controls)?;
    require(
        files == index.files && total == index.retained_bytes,
        "archive inventory differs from exact retained image",
    )
}
fn verify_binding(
    dir: &Path,
    index: &Archive,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<()> {
    require(
        index.format == FORMAT
            && index.currency == pin
            && index.native_head == head
            && !head.is_zero(),
        "archive differs from externally retained native domain/head",
    )?;
    let native = history::manifest(dir)?;
    require(
        native.region == index.region
            && native.bootstrap.currency.id()? == pin
            && native.head()? == head,
        "archive manifest binding mismatch",
    )?;
    storage::verify_pinned_image(dir, authority, pin, head)
}
/// Hold the native lock and preserve all ledger pages/incidents/residue. No keys,
/// signer/caller/wallet journals, contact configurations or transport archives.
pub fn seal(
    source: &Path,
    archive: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<Archive> {
    canonical_path(source)?;
    let node = Store::open_pinned(source, authority, pin, head)?;
    require(
        !exists(&source.join("journal.next"))?,
        "unresolved native manifest residue; preserve source before archive",
    )?;
    fresh(archive, source)?;
    let (files, retained_bytes) = inventory(source, false, &[])?;
    let index = Archive {
        format: FORMAT.into(),
        currency: node.trust.currency()?,
        region: node.chain.region,
        native_head: head,
        retained_bytes,
        files,
    };
    // Capacity and native replay are checked before any output directory.
    let encoded = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
    require(encoded.len() <= MAX_BYTES, "archive index bound")?;
    new_dir(archive)?;
    let lock = new_file(&archive.join("LOCK"), &[])?;
    lock.try_lock().map_err(|e| e.to_string())?;
    new_file(&archive.join("ARCHIVING"), SEALING)?;
    sync(archive)?;
    let data = archive.join("data");
    new_dir(&data)?;
    copy_image(source, &data, &index, false, |_| Ok(()))?;
    same_image(&data, &index, &[])?;
    verify_binding(&data, &index, authority, pin, head)?;
    let (after, bytes) = inventory(source, false, &[])?;
    require(
        after == index.files
            && bytes == retained_bytes
            && history::manifest(source)?.head()? == head,
        "native source changed while sealing archive",
    )?;
    new_file(&archive.join("archive.json"), &encoded)?;
    sync(archive)?;
    require(
        read(&archive.join("ARCHIVING"), true)? == SEALING,
        "archive publication marker changed",
    )?;
    fs::remove_file(archive.join("ARCHIVING")).map_err(io)?;
    sync(archive)?;
    Ok(index)
}
fn open_archive(archive: &Path, authority: &str, pin: Hash, head: Hash) -> Result<(File, Archive)> {
    canonical_path(archive)?;
    private_dir(archive)?;
    require(
        !exists(&archive.join("ARCHIVING"))?,
        "archive publication incomplete; retain it unchanged",
    )?;
    let path = archive.join("LOCK");
    file_metadata(&fs::symlink_metadata(&path).map_err(io)?, true)?;
    let mut opt = OpenOptions::new();
    opt.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opt.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let lock = opt.open(path).map_err(io)?;
    file_metadata(&lock.metadata().map_err(io)?, true)?;
    lock.try_lock().map_err(|e| e.to_string())?;
    require(
        lock.metadata().map_err(io)?.len() == 0,
        "archive lock data refused",
    )?;
    for entry in fs::read_dir(archive).map_err(io)? {
        let name = entry.map_err(io)?.file_name();
        require(
            matches!(name.to_str(), Some("LOCK" | "archive.json" | "data")),
            "unexpected archive root entry",
        )?;
    }
    let raw = read(&archive.join("archive.json"), true)?;
    let index: Archive = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    require(
        serde_json::to_vec(&index).map_err(|e| e.to_string())? == raw,
        "noncanonical archive index",
    )?;
    let data = archive.join("data");
    private_dir(&data)?;
    // Build the inventory from fixed native names; never traverse index paths.
    same_image(&data, &index, &[])?;
    verify_binding(&data, &index, authority, pin, head)?;
    Ok((lock, index))
}
pub fn restore(
    archive: &Path,
    target: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<Archive> {
    restore_inner(archive, target, authority, pin, head, |_| Ok(()))
}
fn restore_inner(
    archive: &Path,
    target: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
    copied: impl FnMut(usize) -> Result<()>,
) -> Result<Archive> {
    fresh(target, archive)?;
    let (_archive_lock, index) = open_archive(archive, authority, pin, head)?;
    new_dir(target)?;
    let target_lock = new_file(&target.join("LOCK"), &[])?;
    target_lock.try_lock().map_err(|e| e.to_string())?;
    new_file(&target.join("RESTORING"), MARKER)?;
    sync(target)?;
    copy_image(&archive.join("data"), target, &index, true, copied)?;
    same_image(target, &index, &["LOCK", "RESTORING"])?;
    verify_binding(target, &index, authority, pin, head)?;
    same_image(&archive.join("data"), &index, &[])?;
    require(
        read(&target.join("RESTORING"), true)? == MARKER,
        "restore interruption marker changed",
    )?;
    fs::remove_file(target.join("RESTORING")).map_err(io)?;
    sync(target)?;
    Ok(index)
}
#[cfg(test)]
pub(crate) fn interrupt_restore(
    archive: &Path,
    target: &Path,
    authority: &str,
    pin: Hash,
    head: Hash,
) -> Result<Archive> {
    restore_inner(archive, target, authority, pin, head, |n| {
        require(n < 2, "injected interruption after copied native files")
    })
}
