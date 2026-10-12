//! Bounded public byte custody. Digests and receipts grant no ledger authority.
use super::*;
use sha2::Sha512;
use std::{
    collections::BTreeSet,
    ffi::CString,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
};
const DOMAIN: &[u8] = b"RLD-PQ-PUBLIC-CARRIAGE-CANDIDATE-V1\0";
const ARCHIVE: &[u8] = b"RLD-PQ-PUBLIC-ARCHIVE-CANDIDATE-V1\0";
const MAX_PACKET: usize = 12288;
const MAX_FILES: usize = 256;
const MAX_BYTES: u64 = (MAX_FILES * MAX_PACKET + 64) as u64;
struct Fragment<'a> {
    total: usize,
    count: usize,
    index: usize,
    root: [u8; 64],
    data: &'a [u8],
}
fn parse(raw: &[u8]) -> Result<Fragment<'_>> {
    let h = DOMAIN.len();
    ensure!(
        raw.starts_with(DOMAIN) && (h + 72..=MAX_PACKET).contains(&raw.len()),
        "public fragment format/size refused"
    );
    let total = u32::from_be_bytes(raw[h..h + 4].try_into()?) as usize;
    let count = u16::from_be_bytes(raw[h + 4..h + 6].try_into()?) as usize;
    let index = u16::from_be_bytes(raw[h + 6..h + 8].try_into()?) as usize;
    ensure!(
        (1..=32768).contains(&total)
            && count == total.div_ceil(12000)
            && count <= 3
            && index < count,
        "public fragment whole/count/index refused"
    );
    let data = &raw[h + 72..];
    ensure!(
        data.len() == 12000.min(total - index * 12000),
        "public fragment canonical length refused"
    );
    Ok(Fragment {
        total,
        count,
        index,
        root: raw[h + 8..h + 72].try_into()?,
        data,
    })
}
fn assemble(parts: &[Vec<u8>], expected: &[u8; 64]) -> Result<Vec<u8>> {
    ensure!(
        !parts.is_empty() && parts.len() <= 3,
        "public whole is incomplete or exceeds fragment inventory"
    );
    let mut decoded = parts.iter().map(|p| parse(p)).collect::<Result<Vec<_>>>()?;
    let total = decoded[0].total;
    let count = decoded[0].count;
    ensure!(
        parts.len() == count
            && decoded
                .iter()
                .all(|p| p.total == total && p.count == count && p.root == *expected),
        "public whole missing/mixed fragments"
    );
    decoded.sort_by_key(|p| p.index);
    ensure!(
        decoded.iter().enumerate().all(|(n, p)| n == p.index),
        "duplicate public fragments"
    );
    let raw = decoded
        .iter()
        .flat_map(|p| p.data.iter().copied())
        .collect::<Vec<_>>();
    ensure!(
        raw.len() == total && Sha512::digest(&raw).as_slice() == expected,
        "complete public bytes fail length/root"
    );
    Ok(raw)
}
fn manifest(raw: &[u8]) -> Result<Vec<(usize, [u8; 64])>> {
    let h = ARCHIVE.len();
    ensure!(
        raw.starts_with(ARCHIVE) && raw.len() >= h + 2,
        "archive manifest format refused"
    );
    let count = u16::from_be_bytes(raw[h..h + 2].try_into()?) as usize;
    ensure!(
        (1..=64).contains(&count) && raw.len() == h + 2 + count * 68,
        "archive manifest count/canonical size refused"
    );
    let mut roots = BTreeSet::new();
    let mut total = 0;
    let mut rows = Vec::new();
    for entry in raw[h + 2..].as_chunks::<68>().0 {
        let size = u32::from_be_bytes(entry[..4].try_into()?) as usize;
        let root: [u8; 64] = entry[4..].try_into()?;
        ensure!(
            (1..=32768).contains(&size) && roots.insert(root),
            "archive entry size or duplicate root refused"
        );
        total += size;
        ensure!(total <= 2097152, "archive aggregate byte bound");
        rows.push((size, root));
    }
    Ok(rows)
}
struct Spool {
    root: PathBuf,
    dir: File,
    _lock: File,
    expected: [u8; 64],
}
impl Spool {
    fn open(root: &Path, expected: [u8; 64], create: bool) -> Result<Self> {
        if create {
            fs::DirBuilder::new().mode(0o700).create(root)?;
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        let metadata = dir.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::getuid() } && metadata.mode() & 0o077 == 0,
            "owned private spool directory required"
        );
        if create {
            ensure!(
                fs::read_dir(root)?.next().is_none(),
                "fresh empty public spool required"
            );
            for (name, raw) in [("expected-root", expected.as_slice()), ("lock", &[][..])] {
                let mut f = Self::file(&dir, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
                f.write_all(raw)?;
                f.sync_all()?;
            }
            dir.sync_all()?;
        }
        let lock = Self::file(&dir, "lock", libc::O_RDONLY)?;
        ensure!(lock.metadata()?.len() == 0, "spool lock file differs");
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "public spool is busy"
        );
        let store = Self {
            root: root.to_path_buf(),
            dir,
            _lock: lock,
            expected,
        };
        ensure!(
            store.read("expected-root")? == expected,
            "independently retained spool root differs"
        );
        store.inventory()?;
        Ok(store)
    }
    fn file(dir: &File, name: &str, flags: i32) -> Result<File> {
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "spool leaf name refused"
        );
        let name = CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0o600,
            )
        };
        ensure!(fd >= 0, "spool file open refused");
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == unsafe { libc::getuid() }
                && meta.mode() & 0o077 == 0
                && meta.len() <= MAX_PACKET as u64,
            "bounded owned private regular packet required"
        );
        Ok(file)
    }
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let f = Self::file(&self.dir, name, libc::O_RDONLY)?;
        let mut raw = Vec::new();
        f.take((MAX_PACKET + 1) as u64).read_to_end(&mut raw)?;
        ensure!(raw.len() <= MAX_PACKET, "packet grew beyond bound");
        Ok(raw)
    }
    fn inventory(&self) -> Result<(Vec<String>, u64)> {
        let mut names = Vec::new();
        let mut total = 0;
        for item in fs::read_dir(&self.root)? {
            let name = item?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("spool name must be UTF8"))?;
            let f = Self::file(&self.dir, &name, libc::O_RDONLY)?;
            total += f.metadata()?.len();
            names.push(name);
            ensure!(
                names.len() <= MAX_FILES && total <= MAX_BYTES,
                "all retained spool residue counts toward capacity"
            );
        }
        names.sort();
        Ok((names, total))
    }
    fn manifest(&self) -> Result<Vec<(usize, [u8; 64])>> {
        manifest(&assemble(&[self.read("manifest.packet")?], &self.expected)?)
    }
    fn accept(&self, packet: &[u8]) -> Result<()> {
        let fragment = parse(packet)?;
        let (names, total) = self.inventory()?;
        let name = if fragment.root == self.expected {
            ensure!(
                fragment.count == 1 && fragment.index == 0,
                "archive manifest requires one complete packet"
            );
            manifest(&assemble(&[packet.to_vec()], &self.expected)?)?;
            "manifest.packet".into()
        } else {
            ensure!(
                self.manifest()?.contains(&(fragment.total, fragment.root)),
                "entry not bound by retained ordered manifest"
            );
            format!("part-{}-{}", hex::encode(fragment.root), fragment.index)
        };
        if names.contains(&name) {
            ensure!(self.read(&name)? == packet, "existing custody bytes differ");
            Self::file(&self.dir, &name, libc::O_RDONLY)?.sync_all()?;
            self.dir.sync_all()?;
            return Ok(());
        }
        ensure!(
            names.len() + 2 <= MAX_FILES && total + 2 * packet.len() as u64 <= MAX_BYTES,
            "staging plus final custody exceeds capacity"
        );
        let sequence = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let partial = format!("partial-{}-{sequence}", std::process::id());
        let mut file = Self::file(
            &self.dir,
            &partial,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        file.write_all(packet)?;
        file.sync_all()?;
        self.dir.sync_all()?;
        let source = CString::new(partial)?;
        let target = CString::new(name)?;
        ensure!(
            unsafe {
                libc::linkat(
                    self.dir.as_raw_fd(),
                    source.as_ptr(),
                    self.dir.as_raw_fd(),
                    target.as_ptr(),
                    0,
                )
            } == 0,
            "immutable packet publication failed; staging residue retained"
        );
        self.dir.sync_all()?;
        ensure!(
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), source.as_ptr(), 0) } == 0,
            "published packet retained with staging residue"
        );
        self.dir.sync_all()?;
        Ok(())
    }
    fn complete(&self) -> Result<Vec<Vec<u8>>> {
        let rows = self.manifest()?;
        let (names, _) = self.inventory()?;
        let mut result = Vec::new();
        for (size, root) in rows {
            let prefix = format!("part-{}-", hex::encode(root));
            let parts = names
                .iter()
                .filter(|n| n.starts_with(&prefix))
                .map(|n| self.read(n))
                .collect::<Result<Vec<_>>>()?;
            let raw = assemble(&parts, &root)?;
            ensure!(raw.len() == size, "entry differs from ordered manifest");
            result.push(raw);
        }
        Ok(result)
    }
}
use std::time::SystemTime;
pub(super) fn run(root: &Path, pin: &str, action: PqSpoolAction) -> Result<Value> {
    ensure!(
        pin.len() == 128
            && pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "independent root requires canonical SHA512"
    );
    let expected: [u8; 64] = hex::decode(pin)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA512 length"))?;
    let store = Spool::open(root, expected, matches!(action, PqSpoolAction::Init))?;
    let value = match action {
        PqSpoolAction::Init => json!({"fresh_public_spool":true}),
        PqSpoolAction::Accept { packet } => {
            ensure!(
                !packet.is_empty() && packet.len() <= 193,
                "public packet inventory bound"
            );
            for path in &packet {
                let mut f = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                    .open(path)?;
                ensure!(
                    f.metadata()?.is_file() && f.metadata()?.len() <= MAX_PACKET as u64,
                    "public packet input bound/type"
                );
                let mut raw = Vec::new();
                (&mut f)
                    .take((MAX_PACKET + 1) as u64)
                    .read_to_end(&mut raw)?;
                store.accept(&raw)?;
            }
            json!({"durable_packet_count":packet.len()})
        }
        PqSpoolAction::Complete { output } => {
            let entries = store.complete()?;
            fs::DirBuilder::new().mode(0o700).create(&output)?;
            for (n, raw) in entries.iter().enumerate() {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(output.join(format!("entry-{n:04}.bin")))?;
                file.write_all(raw)?;
                file.sync_all()?;
            }
            File::open(&output)?.sync_all()?;
            json!({"complete_entries":entries.len()})
        }
    };
    let mut value = value;
    value["monetary_authority"] = json!(false);
    value["installed"] = json!(false);
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn split(raw: &[u8]) -> Vec<Vec<u8>> {
        let hash = Sha512::digest(raw);
        let count = raw.len().div_ceil(12000);
        raw.chunks(12000)
            .enumerate()
            .map(|(n, p)| {
                let mut bytes = DOMAIN.to_vec();
                bytes.extend((raw.len() as u32).to_be_bytes());
                bytes.extend((count as u16).to_be_bytes());
                bytes.extend((n as u16).to_be_bytes());
                bytes.extend(hash);
                bytes.extend(p);
                bytes
            })
            .collect()
    }
    #[test]
    fn fixed_fragments_reject_mixing_duplicates_corruption_and_incomplete_input() {
        let raw = vec![42; 29679];
        let parts = split(&raw);
        assert_eq!(
            parts.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![12108, 12108, 5787]
        );
        let pin = Sha512::digest(&raw).into();
        assert_eq!(assemble(&parts, &pin).unwrap(), raw);
        assert!(assemble(&parts[..2], &pin).is_err());
        let mut bad = parts.clone();
        bad[1] = bad[0].clone();
        assert!(assemble(&bad, &pin).is_err());
        let mut bad = parts;
        *bad[2].last_mut().unwrap() ^= 1;
        assert!(assemble(&bad, &pin).is_err());
    }
}
