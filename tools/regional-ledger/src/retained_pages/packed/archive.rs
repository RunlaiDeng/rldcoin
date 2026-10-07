//! Fresh immutable packed byte archive candidate, not a Native store or recovery.
//! Caller-supplied current scope/head and complete Native semantic replay remain
//! mandatory. Interrupted targets refuse and retain all original residue.
use super::super::{bytes, decode, lock, make_dir, next_head, private_dir, Page, Scope, PAGE};
use super::{
    checked_pages, encode_complete_page_pack_candidate, header, take,
    verify_complete_page_pack_candidate, PackedPageContextCandidateV1, MAX_PACKED_PAGES_CANDIDATE,
};
use crate::{history, keystore, require, Hash, Result, MAX_BYTES};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Digest;
use std::{
    fs::{self, File},
    marker::PhantomData,
    path::{Path, PathBuf},
};

const FORMAT: &str = "RLD-NATIVE-IMMUTABLE-PACKED-ARCHIVE-CANDIDATE-V1";
const LOSSLESS_FORMAT: &str = "RLD-NATIVE-IMMUTABLE-LOSSLESS-PACKED-ARCHIVE-CANDIDATE-V1";
const MANIFEST: &str = "packed.json";
const MARKER: &str = "ARCHIVING";
const OBJECTS: &str = "packs";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    scope: Scope,
    packs: Vec<history::Reference>,
    count: u64,
    head: Hash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    original_packs: Vec<history::Reference>,
}
fn err(_: std::io::Error) -> String {
    "packed private archive operation unavailable".into()
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(err(e)),
    }
}
fn name(hash: Hash) -> String {
    format!("{}.pack", hash.to_hex())
}
fn usage(dir: &Path) -> Result<(usize, u64)> {
    private_dir(dir)?;
    private_dir(&dir.join(OBJECTS))?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).map_err(err)? {
        let p = entry.map_err(err)?.path();
        match p.file_name().and_then(|v| v.to_str()) {
            Some(OBJECTS) => {}
            Some("LOCK" | MANIFEST | MARKER) => paths.push(p),
            _ => return Err("unexpected packed archive root entry".into()),
        }
    }
    for entry in fs::read_dir(dir.join(OBJECTS)).map_err(err)? {
        let p = entry.map_err(err)?.path();
        let n = p
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("packed object name encoding")?;
        require(
            n.len() == 69
                && n.ends_with(".pack")
                && n.as_bytes()[..64]
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
            "unexpected packed object name",
        )?;
        paths.push(p);
        require(
            paths.len() <= history::MAX_FILES,
            "packed complete archive file capacity",
        )?;
    }
    let mut total = 0u64;
    for p in &paths {
        total = total
            .checked_add(keystore::private_read(p, MAX_BYTES)?.len() as u64)
            .ok_or("packed archive byte overflow")?;
        require(
            total <= history::MAX_ARCHIVE_BYTES,
            "packed complete archive byte capacity",
        )?;
    }
    require(
        paths.len() <= history::MAX_FILES,
        "packed complete archive file capacity",
    )?;
    Ok((paths.len(), total))
}
fn preflight(dir: &Path, new_files: usize, new_bytes: u64) -> Result<()> {
    let (files, retained) = usage(dir)?;
    require(
        files
            .checked_add(new_files)
            .is_some_and(|n| n <= history::MAX_FILES)
            && retained
                .checked_add(new_bytes)
                .is_some_and(|n| n <= history::MAX_ARCHIVE_BYTES),
        "packed complete archive retained capacity",
    )
}
struct Builder {
    context: PackedPageContextCandidateV1,
    head: Hash,
    count: u64,
    packs: Vec<history::Reference>,
    originals: Vec<history::Reference>,
    lossless: bool,
}
impl Builder {
    fn flush<T: Serialize + DeserializeOwned>(
        &mut self,
        dir: &Path,
        group: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        if group.is_empty() {
            return Ok(());
        }
        let pages = group.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let verified = checked_pages::<T>(&self.context, &pages)?;
        let (original_ref, original) =
            encode_complete_page_pack_candidate::<T>(&self.context, &pages)?;
        let (reference, raw) = if self.lossless {
            super::lossless::encode_lossless_complete_pack_candidate::<T>(
                &self.context,
                &original_ref,
                &original,
            )?
        } else {
            (original_ref.clone(), original)
        };
        require(
            self.packs
                .len()
                .checked_add(1)
                .is_some_and(|n| n <= history::MAX_FILES),
            "packed complete archive reference capacity",
        )?;
        let mut proposed = self.packs.clone();
        proposed.push(reference.clone());
        let mut originals = self.originals.clone();
        if self.lossless {
            originals.push(original_ref);
        }
        let future = bytes(&Manifest {
            format: if self.lossless {
                LOSSLESS_FORMAT
            } else {
                FORMAT
            }
            .into(),
            scope: self.context.scope.clone(),
            packs: proposed,
            count: self.count,
            head: self.head,
            original_packs: originals.clone(),
        })?;
        let reserved = (raw.len() as u64)
            .checked_add(future.len() as u64)
            .ok_or("packed future manifest overflow")?;
        preflight(dir, 2, reserved)?;
        keystore::private_create(&dir.join(OBJECTS).join(name(reference.hash)), &raw)?;
        self.context.first_record = verified.next_record;
        self.context.previous_page = Some(verified.last_page);
        self.context.previous_pack = Some(reference.hash);
        self.packs.push(reference);
        self.originals = originals;
        group.clear();
        Ok(())
    }
}
/// Locked, finite integrity-only archive. No ledger/signer state is serialized.
pub struct PackedArchiveCandidate<T> {
    dir: PathBuf,
    _lock: File,
    manifest: Manifest,
    _type: PhantomData<T>,
}
impl<T: Serialize + DeserializeOwned> PackedArchiveCandidate<T> {
    /// Only fresh caller-supplied pages. Wrong ending head or interruption
    /// retains ARCHIVING; existing private streams never convert or recover.
    pub fn seal(
        dir: &Path,
        scope: Scope,
        independently_expected_head: Hash,
        complete_pages: impl IntoIterator<Item = Result<Vec<u8>>>,
    ) -> Result<Self> {
        Self::seal_inner(
            dir,
            scope,
            independently_expected_head,
            complete_pages,
            None,
            false,
        )
    }
    /// Separate explicit format; ordinary raw opens never reinterpret it.
    pub fn seal_lossless_candidate(
        dir: &Path,
        scope: Scope,
        independently_expected_head: Hash,
        complete_pages: impl IntoIterator<Item = Result<Vec<u8>>>,
    ) -> Result<Self> {
        Self::seal_inner(
            dir,
            scope,
            independently_expected_head,
            complete_pages,
            None,
            true,
        )
    }
    fn seal_inner(
        dir: &Path,
        scope: Scope,
        expected: Hash,
        complete_pages: impl IntoIterator<Item = Result<Vec<u8>>>,
        interrupt: Option<u8>,
        lossless: bool,
    ) -> Result<Self> {
        private_dir(dir.parent().ok_or("packed archive parent missing")?)?;
        require(!exists(dir)?, "packed archive requires absent fresh target")?;
        make_dir(dir)?;
        keystore::private_create(&dir.join("LOCK"), b"")?;
        let guard = lock(dir)?;
        make_dir(&dir.join(OBJECTS))?;
        let format = if lossless { LOSSLESS_FORMAT } else { FORMAT };
        keystore::private_create(&dir.join(MARKER), &bytes(&(format, &scope, expected))?)?;
        let mut builder = Builder {
            head: scope.initial()?,
            count: 0,
            packs: vec![],
            originals: vec![],
            lossless,
            context: PackedPageContextCandidateV1 {
                scope: scope.clone(),
                first_record: 0,
                previous_page: None,
                previous_pack: None,
            },
        };
        let mut group = Vec::new();
        let mut previous = None;
        let mut held = 0usize;
        for page in complete_pages {
            let raw = page?;
            require(
                !raw.is_empty() && raw.len() <= MAX_BYTES,
                "packed staged complete page byte capacity",
            )?;
            let overhead = header(&builder.context, 1)?.len();
            if !group.is_empty()
                && (group.len() == MAX_PACKED_PAGES_CANDIDATE
                    || held
                        .checked_add(4)
                        .and_then(|n| n.checked_add(raw.len()))
                        .and_then(|n| n.checked_add(overhead))
                        .is_none_or(|n| n > MAX_BYTES))
            {
                builder.flush::<T>(dir, &mut group)?;
                held = 0;
                if interrupt == Some(0) {
                    return Err("injected after retained complete pack".into());
                }
            }
            let page: Page<T> = decode(&raw)?;
            require(
                page.format == super::super::FORMAT
                    && page.scope == scope
                    && page.first == builder.count
                    && page.previous == previous
                    && page.records.len() == PAGE,
                "packed seal complete original page domain/order/count",
            )?;
            for record in &page.records {
                builder.head = next_head(builder.head, builder.count, record)?;
                builder.count = builder
                    .count
                    .checked_add(1)
                    .ok_or("packed seal record overflow")?;
            }
            previous = Some(Hash(sha2::Sha256::digest(&raw).into()));
            held = held
                .checked_add(4)
                .and_then(|n| n.checked_add(raw.len()))
                .ok_or("packed staged byte overflow")?;
            require(
                held.checked_add(header(&builder.context, 1)?.len())
                    .is_some_and(|n| n <= MAX_BYTES),
                "packed staged object byte capacity",
            )?;
            group.push(raw);
        }
        builder.flush::<T>(dir, &mut group)?;
        if interrupt == Some(0) {
            return Err("injected after retained complete pack".into());
        }
        require(
            builder.head == expected,
            "packed archive independently expected complete head differs",
        )?;
        let manifest = Manifest {
            format: format.into(),
            scope,
            packs: builder.packs,
            count: builder.count,
            head: builder.head,
            original_packs: builder.originals,
        };
        let raw = bytes(&manifest)?;
        preflight(dir, 1, raw.len() as u64)?;
        keystore::private_create(&dir.join(MANIFEST), &raw)?;
        if interrupt == Some(1) {
            return Err("injected after retained complete manifest".into());
        }
        fs::remove_file(dir.join(MARKER)).map_err(err)?;
        File::open(dir).map_err(err)?.sync_all().map_err(err)?;
        let result = Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            _type: PhantomData,
        };
        result.visit(expected, |_| Ok(()))?;
        Ok(result)
    }
    pub fn open(dir: &Path, independently_scope: &Scope, independently_head: Hash) -> Result<Self> {
        Self::open_inner(dir, independently_scope, independently_head, None)
    }
    /// Require a separately retained COMPLETE current manifest reference before
    /// parsing its encoded/decoded pack references or inflating any object.
    pub fn open_lossless_candidate(
        dir: &Path,
        independently_scope: &Scope,
        independently_head: Hash,
        independently_manifest: &history::Reference,
    ) -> Result<Self> {
        Self::open_inner(
            dir,
            independently_scope,
            independently_head,
            Some(independently_manifest),
        )
    }
    fn open_inner(
        dir: &Path,
        independently_scope: &Scope,
        independently_head: Hash,
        independently_manifest: Option<&history::Reference>,
    ) -> Result<Self> {
        private_dir(dir)?;
        let guard = lock(dir)?;
        require(
            !exists(&dir.join(MARKER))?,
            "incomplete packed archive; retain original residue",
        )?;
        let raw = keystore::private_read(&dir.join(MANIFEST), MAX_BYTES)?;
        if let Some(reference) = independently_manifest {
            require(
                reference.bytes == raw.len()
                    && reference.hash == Hash(sha2::Sha256::digest(&raw).into()),
                "lossless archive independent complete manifest differs",
            )?;
        }
        let manifest: Manifest = decode(&raw)?;
        require(
            manifest.format
                == (if independently_manifest.is_some() {
                    LOSSLESS_FORMAT
                } else {
                    FORMAT
                })
                && manifest.scope == *independently_scope
                && (independently_manifest.is_some() || manifest.original_packs.is_empty()),
            "packed archive current scope/format; no conversion",
        )?;
        let archive = Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            _type: PhantomData,
        };
        archive.visit(independently_head, |_| Ok(()))?;
        Ok(archive)
    }
    /// Native consumers must stage all semantic replay locally and publish no
    /// ledger, signer or value state until this complete ordered call succeeds.
    pub fn visit(
        &self,
        independently_head: Hash,
        mut consumer: impl FnMut(&T) -> Result<()>,
    ) -> Result<u64> {
        require(
            !exists(&self.dir.join(MARKER))?,
            "incomplete packed archive; retain original residue",
        )?;
        usage(&self.dir)?;
        require(
            *keystore::private_read(&self.dir.join(MANIFEST), MAX_BYTES)? == bytes(&self.manifest)?,
            "held packed archive disk manifest differs",
        )?;
        require(
            self.manifest.packs.len() <= history::MAX_FILES
                && self.manifest.head == independently_head,
            "packed archive current head/reference capacity",
        )?;
        let lossless = self.manifest.format == LOSSLESS_FORMAT;
        require(
            (lossless && self.manifest.original_packs.len() == self.manifest.packs.len())
                || (!lossless
                    && self.manifest.format == FORMAT
                    && self.manifest.original_packs.is_empty()),
            "packed archive exact format/complete original references",
        )?;
        let mut context = PackedPageContextCandidateV1 {
            scope: self.manifest.scope.clone(),
            first_record: 0,
            previous_page: None,
            previous_pack: None,
        };
        let mut head = context.scope.initial()?;
        let mut count = 0u64;
        for (position, reference) in self.manifest.packs.iter().enumerate() {
            let raw = keystore::private_read(
                &self.dir.join(OBJECTS).join(name(reference.hash)),
                MAX_BYTES,
            )?;
            let (verified, decoded);
            let complete_raw: &[u8] = if lossless {
                let restored = super::lossless::verify_lossless_complete_pack_candidate::<T>(
                    &context,
                    &self.manifest.original_packs[position],
                    reference,
                    &raw,
                )?;
                verified = restored.complete;
                decoded = restored.original_pack;
                &decoded
            } else {
                verified = verify_complete_page_pack_candidate::<T>(&context, reference, &raw)?;
                &raw
            };
            let mut offset = header(&context, verified.complete_pages.len())?.len();
            for _ in &verified.complete_pages {
                let len =
                    u32::from_be_bytes(take(complete_raw, &mut offset, 4)?.try_into().unwrap())
                        as usize;
                let page: Page<T> = decode(take(complete_raw, &mut offset, len)?)?;
                for record in &page.records {
                    consumer(record)?;
                    head = next_head(head, count, record)?;
                    count = count.checked_add(1).ok_or("packed visit record overflow")?;
                }
            }
            require(
                count == verified.next_record,
                "packed decoded record position differs",
            )?;
            context.first_record = verified.next_record;
            context.previous_page = Some(verified.last_page);
            context.previous_pack = Some(reference.hash);
        }
        require(
            count == self.manifest.count
                && head == self.manifest.head
                && head == independently_head,
            "packed archive exact complete head/count",
        )?;
        Ok(count)
    }
    /// Retain this after successful local sealing; a peer-selected reference is
    /// not an independent latest anchor and cannot initialize Native authority.
    pub fn manifest_reference_candidate(&self) -> Result<history::Reference> {
        let raw = bytes(&self.manifest)?;
        Ok(history::Reference {
            hash: Hash(sha2::Sha256::digest(&raw).into()),
            bytes: raw.len(),
        })
    }
    pub(crate) fn require_scope(&self, scope: &Scope) -> Result<()> {
        require(
            self.manifest.scope == *scope,
            "packed archive Native scope differs",
        )
    }
    pub fn record_count(&self) -> u64 {
        self.manifest.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };
    fn scope() -> Scope {
        Scope {
            implementation: crate::implementation().unwrap(),
            currency: Hash([1; 32]),
            region: Hash([2; 32]),
            admission: Hash([3; 32]),
            purpose: super::super::super::Purpose::Ledger,
            origin: Hash([4; 32]),
        }
    }
    fn fresh_root() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp")
            .canonicalize()
            .unwrap();
        let p = base.join(format!(
            "native-packed-archive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        make_dir(&p).unwrap();
        p
    }
    fn fixture_pages(scope: &Scope, n: usize) -> (Vec<Result<Vec<u8>>>, Hash) {
        let mut previous = None;
        let mut head = scope.initial().unwrap();
        let mut out = Vec::new();
        for i in 0..n {
            let first = (i * PAGE) as u64;
            let records = (first..first + PAGE as u64).collect::<Vec<_>>();
            for r in &records {
                head = next_head(head, *r, r).unwrap();
            }
            let raw = bytes(&Page {
                format: super::super::super::FORMAT.into(),
                scope: scope.clone(),
                first,
                previous,
                records,
            })
            .unwrap();
            previous = Some(Hash(sha2::Sha256::digest(&raw).into()));
            out.push(Ok(raw));
        }
        (out, head)
    }
    fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
        let mut result = BTreeMap::new();
        fn walk(p: &Path, out: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
            for e in fs::read_dir(p).unwrap() {
                let p = e.unwrap().path();
                let m = fs::symlink_metadata(&p).unwrap();
                if m.is_dir() {
                    walk(&p, out);
                } else {
                    out.insert(
                        p.clone(),
                        (
                            Hash(sha2::Sha256::digest(fs::read(&p).unwrap()).into()),
                            m.len(),
                            m.modified().unwrap(),
                        ),
                    );
                }
            }
        }
        walk(root, &mut result);
        result
    }
    #[test]
    fn whole65_pages_use_two_packs_and_cold_child_reads_every_original_record() {
        let root = fresh_root();
        let scope = scope();
        let (pageinputs, head) = fixture_pages(&scope, 65);
        let archive = PackedArchiveCandidate::<u64>::seal(
            &root.join("archive"),
            scope.clone(),
            head,
            pageinputs,
        )
        .unwrap();
        assert_eq!(archive.manifest.packs.len(), 2);
        assert_eq!(archive.record_count(), 1040);
        let mut count = 0;
        archive
            .visit(head, |r| {
                require(*r == count, "complete ordered fixture record")?;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1040);
        drop(archive);
        keystore::private_create(&root.join("scope.json"), &bytes(&scope).unwrap()).unwrap();
        let before = inventory(&root);
        let output = Command::new(std::env::current_exe().unwrap())
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "--exact",
                "retained_pages::packed::archive::tests::cold_child",
                "--ignored",
                "--test-threads=1",
            ])
            .env("RLD_PACKED_ARCHIVE_CHILD_DIR", &root)
            .env("RLD_PACKED_ARCHIVE_CHILD_HEAD", head.to_hex())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(inventory(&root), before);
    }
    #[test]
    #[ignore = "called only by bounded parent with exact fresh synthetic archive"]
    fn cold_child() {
        let root = PathBuf::from(std::env::var_os("RLD_PACKED_ARCHIVE_CHILD_DIR").unwrap());
        let head =
            Hash::from_hex(&std::env::var("RLD_PACKED_ARCHIVE_CHILD_HEAD").unwrap()).unwrap();
        let s: Scope =
            decode(&keystore::private_read(&root.join("scope.json"), MAX_BYTES).unwrap()).unwrap();
        let archive = PackedArchiveCandidate::<u64>::open(&root.join("archive"), &s, head).unwrap();
        let mut count = 0;
        archive
            .visit(head, |r| {
                require(*r == count, "cold complete fixture order")?;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1040);
    }
    #[test]
    fn interruptions_and_wrong_end_head_retain_all_bytes_and_cannot_resume() {
        for boundary in [Some(0), Some(1), None] {
            let root = fresh_root();
            let s = scope();
            let (pageinputs, head) = fixture_pages(&s, 2);
            let expected = if boundary.is_none() {
                Hash([9; 32])
            } else {
                head
            };
            let dir = root.join("failed");
            assert!(PackedArchiveCandidate::<u64>::seal_inner(
                &dir,
                s.clone(),
                expected,
                pageinputs,
                boundary,
                false
            )
            .is_err());
            let before = inventory(&root);
            assert!(dir.join(MARKER).exists());
            assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, head).is_err());
            let (pageinputs, _) = fixture_pages(&s, 2);
            assert!(
                PackedArchiveCandidate::<u64>::seal(&dir, s.clone(), head, pageinputs).is_err()
            );
            assert_eq!(inventory(&root), before);
        }
    }
    #[test]
    fn current_head_lock_missing_pack_and_retained_orphan_capacity_refuse() {
        let root = fresh_root();
        let s = scope();
        let (pageinputs, head) = fixture_pages(&s, 2);
        let dir = root.join("archive");
        let archive =
            PackedArchiveCandidate::<u64>::seal(&dir, s.clone(), head, pageinputs).unwrap();
        assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, head).is_err());
        let first = archive.manifest.packs[0].clone();
        drop(archive);
        let before = inventory(&root);
        assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, Hash([9; 32])).is_err());
        assert_eq!(inventory(&root), before);
        fs::rename(
            dir.join(OBJECTS).join(name(first.hash)),
            root.join("retained-missing.pack"),
        )
        .unwrap();
        let before = inventory(&root);
        assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, head).is_err());
        assert_eq!(inventory(&root), before);
        let root = fresh_root();
        let dir = root.join("capacity");
        let (pageinputs, head) = fixture_pages(&s, 1);
        let archive =
            PackedArchiveCandidate::<u64>::seal(&dir, s.clone(), head, pageinputs).unwrap();
        drop(archive);
        for i in 0..history::MAX_FILES - 2 {
            let h = crate::id("packed-file-capacity-orphan", &i).unwrap();
            keystore::private_create(&dir.join(OBJECTS).join(name(h)), b"").unwrap();
        }
        let before = inventory(&root);
        assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, head)
            .err()
            .unwrap()
            .contains("file capacity"));
        assert_eq!(inventory(&root), before);
    }

    #[test]
    fn lossless65_full_pages_cold_child_requires_exact_manifest_and_raw_open_refuses() {
        let root = fresh_root();
        let s = scope();
        let (pages, head) = fixture_pages(&s, 65);
        let dir = root.join("lossless");
        let archive =
            PackedArchiveCandidate::<u64>::seal_lossless_candidate(&dir, s.clone(), head, pages)
                .unwrap();
        assert_eq!(archive.manifest.packs.len(), 2);
        assert_eq!(archive.manifest.original_packs.len(), 2);
        let manifest = archive.manifest_reference_candidate().unwrap();
        drop(archive);
        keystore::private_create(&root.join("scope.json"), &bytes(&s).unwrap()).unwrap();
        let before = inventory(&root);
        let output = Command::new(std::env::current_exe().unwrap())
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .args([
                "retained_pages::packed::archive::tests::lossless_cold_child",
                "--exact",
                "--ignored",
            ])
            .env("RLD_LOSSLESS_ARCHIVE_CHILD_DIR", &root)
            .env("RLD_LOSSLESS_ARCHIVE_CHILD_HEAD", head.to_hex())
            .env(
                "RLD_LOSSLESS_ARCHIVE_CHILD_MANIFEST_HASH",
                manifest.hash.to_hex(),
            )
            .env(
                "RLD_LOSSLESS_ARCHIVE_CHILD_MANIFEST_BYTES",
                manifest.bytes.to_string(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(PackedArchiveCandidate::<u64>::open(&dir, &s, head).is_err());
        let mut wrong = manifest.clone();
        wrong.hash = Hash([9; 32]);
        assert!(
            PackedArchiveCandidate::<u64>::open_lossless_candidate(&dir, &s, head, &wrong).is_err()
        );
        assert!(PackedArchiveCandidate::<u64>::open_lossless_candidate(
            &dir,
            &s,
            Hash([9; 32]),
            &manifest
        )
        .is_err());
        assert_eq!(inventory(&root), before);
        let held =
            PackedArchiveCandidate::<u64>::open_lossless_candidate(&dir, &s, head, &manifest)
                .unwrap();
        assert!(
            PackedArchiveCandidate::<u64>::open_lossless_candidate(&dir, &s, head, &manifest)
                .is_err()
        );
        drop(held);
    }
    #[test]
    #[ignore = "separate cold process with independent manifest and current head"]
    fn lossless_cold_child() {
        let root = PathBuf::from(std::env::var_os("RLD_LOSSLESS_ARCHIVE_CHILD_DIR").unwrap());
        let s: Scope =
            decode(&keystore::private_read(&root.join("scope.json"), MAX_BYTES).unwrap()).unwrap();
        let head =
            Hash::from_hex(&std::env::var("RLD_LOSSLESS_ARCHIVE_CHILD_HEAD").unwrap()).unwrap();
        let manifest = history::Reference {
            hash: Hash::from_hex(
                &std::env::var("RLD_LOSSLESS_ARCHIVE_CHILD_MANIFEST_HASH").unwrap(),
            )
            .unwrap(),
            bytes: std::env::var("RLD_LOSSLESS_ARCHIVE_CHILD_MANIFEST_BYTES")
                .unwrap()
                .parse()
                .unwrap(),
        };
        let archive = PackedArchiveCandidate::<u64>::open_lossless_candidate(
            &root.join("lossless"),
            &s,
            head,
            &manifest,
        )
        .unwrap();
        let mut count = 0;
        archive
            .visit(head, |record| {
                require(*record == count, "lossless original record order")?;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, 1040);
    }
    #[test]
    fn lossless_interruption_and_missing_original_reference_keep_all_residue() {
        for boundary in [Some(0), Some(1)] {
            let root = fresh_root();
            let s = scope();
            let (pages, head) = fixture_pages(&s, 2);
            let dir = root.join("failed-lossless");
            assert!(PackedArchiveCandidate::<u64>::seal_inner(
                &dir,
                s.clone(),
                head,
                pages,
                boundary,
                true
            )
            .is_err());
            let before = inventory(&root);
            let unavailable = history::Reference {
                hash: Hash([9; 32]),
                bytes: 1,
            };
            assert!(PackedArchiveCandidate::<u64>::open_lossless_candidate(
                &dir,
                &s,
                head,
                &unavailable
            )
            .is_err());
            let (pages, _) = fixture_pages(&s, 2);
            assert!(PackedArchiveCandidate::<u64>::seal_lossless_candidate(
                &dir,
                s.clone(),
                head,
                pages
            )
            .is_err());
            assert_eq!(inventory(&root), before);
        }
        let root = fresh_root();
        let s = scope();
        let (pages, head) = fixture_pages(&s, 1);
        let dir = root.join("malformed-lossless");
        let archive =
            PackedArchiveCandidate::<u64>::seal_lossless_candidate(&dir, s.clone(), head, pages)
                .unwrap();
        let mut manifest = archive.manifest.clone();
        drop(archive);
        manifest.original_packs.clear();
        let raw = bytes(&manifest).unwrap();
        fs::write(dir.join(MANIFEST), &raw).unwrap();
        let pinned = history::Reference {
            hash: Hash(sha2::Sha256::digest(&raw).into()),
            bytes: raw.len(),
        };
        let before = inventory(&root);
        assert!(
            PackedArchiveCandidate::<u64>::open_lossless_candidate(&dir, &s, head, &pinned)
                .is_err()
        );
        assert_eq!(inventory(&root), before);
    }
}
