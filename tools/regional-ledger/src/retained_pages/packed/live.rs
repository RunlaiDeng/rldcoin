//! Appendable exact-byte packing candidate, never a Native Store or signer.
//! Full replay and separately protected latest heads remain caller obligations.
//! Old streams never convert. Interrupted publication refuses and retains bytes.
use super::super::{
    bytes, decode, exists, lock, make_dir, next_head, private_dir, Page, Scope, PAGE,
};
use super::{
    encode_complete_page_pack_candidate, header, lossless, take, PackedPageContextCandidateV1,
    MAX_PACKED_PAGES_CANDIDATE,
};
use crate::{history, keystore, require, Hash, Result, MAX_BYTES};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};

const FORMAT: &str = "RLD-NATIVE-APPENDABLE-LOSSLESS-PAGES-CANDIDATE-V1";
const MANIFEST: &str = "live.json";
const PENDING: &str = "live.next";
const COMMIT: &str = "live.commit";
const OBJECTS: &str = "packs";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    encoded: history::Reference,
    original: history::Reference,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest<T> {
    format: String,
    scope: Scope,
    packs: Vec<Pack>,
    complete: Vec<Page<T>>,
    tail: Vec<T>,
    count: u64,
    head: Hash,
    previous_page: Option<Hash>,
}
#[derive(Serialize)]
struct Object {
    pack: Pack,
    // Complete reversible payload, never a reference to bytes held only in RAM.
    encoded_b64: String,
}
#[derive(Serialize)]
struct Publication<'a, T> {
    expected_head: Hash,
    manifest: &'a Manifest<T>,
    objects: &'a [Object],
}
fn err(_: std::io::Error) -> String {
    "live packed private storage operation failed".into()
}
fn name(hash: Hash) -> String {
    format!("{}.pack", hash.to_hex())
}
fn usage(dir: &Path) -> Result<(usize, u64)> {
    private_dir(dir)?;
    private_dir(&dir.join(OBJECTS))?;
    let mut count = 0usize;
    let mut size = 0u64;
    for directory in [dir.to_path_buf(), dir.join(OBJECTS)] {
        for entry in fs::read_dir(&directory).map_err(err)? {
            let path = entry.map_err(err)?.path();
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("live packed filename")?;
            if directory == dir {
                if filename == OBJECTS {
                    continue;
                }
                require(
                    matches!(filename, "LOCK" | MANIFEST | PENDING | COMMIT),
                    "unexpected live packed root entry",
                )?;
            } else {
                require(
                    filename.len() == 69
                        && filename.ends_with(".pack")
                        && filename.as_bytes()[..64]
                            .iter()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
                    "unexpected live packed object name",
                )?;
            }
            // All retained objects and orphans count, even when not referenced.
            let raw = keystore::private_read(&path, MAX_BYTES)?;
            count = count
                .checked_add(1)
                .ok_or("live packed file count overflow")?;
            size = size
                .checked_add(raw.len() as u64)
                .ok_or("live packed byte count overflow")?;
            require(
                count <= history::MAX_FILES && size <= history::MAX_ARCHIVE_BYTES,
                "live packed retained archive capacity",
            )?;
        }
    }
    Ok((count, size))
}
fn visit_page<T: Serialize + DeserializeOwned>(
    page: &Page<T>,
    scope: &Scope,
    index: &mut u64,
    head: &mut Hash,
    previous: &mut Option<Hash>,
    consumer: &mut impl FnMut(&T) -> Result<()>,
) -> Result<()> {
    require(
        page.format == super::super::FORMAT
            && page.scope == *scope
            && page.first == *index
            && page.previous == *previous
            && page.records.len() == PAGE,
        "live packed complete page domain/order/predecessor",
    )?;
    let raw = bytes(page)?;
    for record in &page.records {
        consumer(record)?;
        *head = next_head(*head, *index, record)?;
        *index = index
            .checked_add(1)
            .ok_or("live packed record count overflow")?;
    }
    *previous = Some(Hash(Sha256::digest(raw).into()));
    Ok(())
}

/// Integrity-only locked byte stream. No authority or execution cache is held.
pub struct AppendablePackedStreamCandidate<T> {
    dir: PathBuf,
    _lock: File,
    manifest: Manifest<T>,
    healthy: bool,
    #[cfg(test)]
    interruption: Option<u8>,
}
impl<T: Clone + Serialize + DeserializeOwned> AppendablePackedStreamCandidate<T> {
    pub fn create(dir: &Path, scope: Scope) -> Result<Self> {
        private_dir(dir.parent().ok_or("live packed parent missing")?)?;
        require(
            !exists(dir)?,
            "live packed creation requires absent fresh directory",
        )?;
        make_dir(dir)?;
        keystore::private_create(&dir.join("LOCK"), b"")?;
        let guard = lock(dir)?;
        make_dir(&dir.join(OBJECTS))?;
        let manifest = Manifest {
            format: FORMAT.into(),
            head: scope.initial()?,
            scope,
            packs: vec![],
            complete: vec![],
            tail: vec![],
            count: 0,
            previous_page: None,
        };
        keystore::private_create(&dir.join(MANIFEST), &bytes(&manifest)?)?;
        Ok(Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            healthy: true,
            #[cfg(test)]
            interruption: None,
        })
    }
    pub fn open(dir: &Path, scope: &Scope, expected_head: Hash) -> Result<Self> {
        private_dir(dir)?;
        let guard = lock(dir)?;
        usage(dir)?;
        require(
            !exists(&dir.join(PENDING))? && !exists(&dir.join(COMMIT))?,
            "incomplete live packed publication; retain original residue",
        )?;
        let manifest: Manifest<T> =
            decode(&keystore::private_read(&dir.join(MANIFEST), MAX_BYTES)?)?;
        require(
            manifest.format == FORMAT && manifest.scope == *scope,
            "live packed format/scope differs; no conversion",
        )?;
        let stream = Self {
            dir: dir.into(),
            _lock: guard,
            manifest,
            healthy: true,
            #[cfg(test)]
            interruption: None,
        };
        stream.visit(expected_head, |_| Ok(()))?;
        Ok(stream)
    }
    /// The observation is not an independent latest head or Native authority.
    pub fn storage_head(&self) -> Hash {
        self.manifest.head
    }
    pub fn record_count(&self) -> u64 {
        self.manifest.count
    }

    /// Stage any semantic execution until this entire call succeeds. Each cold
    /// call reconstructs every exact original typed record, including the tail.
    pub fn visit(
        &self,
        expected_head: Hash,
        mut consumer: impl FnMut(&T) -> Result<()>,
    ) -> Result<u64> {
        require(
            self.healthy && !exists(&self.dir.join(PENDING))? && !exists(&self.dir.join(COMMIT))?,
            "incomplete live packed publication; retain original residue",
        )?;
        usage(&self.dir)?;
        require(
            *keystore::private_read(&self.dir.join(MANIFEST), MAX_BYTES)? == bytes(&self.manifest)?,
            "live packed disk manifest differs from locked current bytes",
        )?;
        require(
            self.manifest.format == FORMAT
                && self.manifest.packs.len() <= history::MAX_FILES
                && self.manifest.complete.len() < MAX_PACKED_PAGES_CANDIDATE
                && self.manifest.tail.len() < PAGE,
            "live packed manifest/page/tail capacity",
        )?;
        let mut index = 0u64;
        let mut head = self.manifest.scope.initial()?;
        let mut previous = None;
        let mut previous_pack = None;
        for pack in &self.manifest.packs {
            let context = PackedPageContextCandidateV1 {
                scope: self.manifest.scope.clone(),
                first_record: index,
                previous_page: previous,
                previous_pack,
            };
            let raw = keystore::private_read(
                &self.dir.join(OBJECTS).join(name(pack.encoded.hash)),
                MAX_BYTES,
            )?;
            let verified = lossless::verify_lossless_complete_pack_candidate::<T>(
                &context,
                &pack.original,
                &pack.encoded,
                &raw,
            )?;
            let original = &verified.original_pack;
            let mut offset = header(&context, verified.complete.complete_pages.len())?.len();
            for _ in &verified.complete.complete_pages {
                let length = u32::from_be_bytes(take(original, &mut offset, 4)?.try_into().unwrap())
                    as usize;
                let page: Page<T> = decode(take(original, &mut offset, length)?)?;
                visit_page(
                    &page,
                    &self.manifest.scope,
                    &mut index,
                    &mut head,
                    &mut previous,
                    &mut consumer,
                )?;
            }
            require(
                offset == original.len()
                    && index == verified.complete.next_record
                    && previous == Some(verified.complete.last_page),
                "live packed complete pack cursor differs",
            )?;
            previous_pack = Some(pack.encoded.hash);
        }
        for page in &self.manifest.complete {
            visit_page(
                page,
                &self.manifest.scope,
                &mut index,
                &mut head,
                &mut previous,
                &mut consumer,
            )?;
        }
        for record in &self.manifest.tail {
            consumer(record)?;
            head = next_head(head, index, record)?;
            index = index
                .checked_add(1)
                .ok_or("live packed record count overflow")?;
        }
        require(
            index == self.manifest.count
                && head == self.manifest.head
                && head == expected_head
                && previous == self.manifest.previous_page,
            "live packed exact latest head/count/page differs",
        )?;
        Ok(index)
    }

    fn flush(manifest: &mut Manifest<T>, objects: &mut Vec<Object>) -> Result<()> {
        if manifest.complete.is_empty() {
            return Ok(());
        }
        let first = &manifest.complete[0];
        let context = PackedPageContextCandidateV1 {
            scope: manifest.scope.clone(),
            first_record: first.first,
            previous_page: first.previous,
            previous_pack: manifest.packs.last().map(|p| p.encoded.hash),
        };
        let pages = manifest
            .complete
            .iter()
            .map(bytes)
            .collect::<Result<Vec<_>>>()?;
        let (original, raw) = encode_complete_page_pack_candidate::<T>(
            &context,
            &pages.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        )?;
        let (encoded, compressed) =
            lossless::encode_lossless_complete_pack_candidate::<T>(&context, &original, &raw)?;
        let pack = Pack { encoded, original };
        objects.push(Object {
            pack: pack.clone(),
            encoded_b64: STANDARD.encode(compressed),
        });
        manifest.packs.push(pack);
        manifest.complete.clear();
        Ok(())
    }
    pub fn append(&mut self, records: &[T], expected_head: Hash) -> Result<Hash> {
        self.append_accounted(records, expected_head, 0, 0)
    }
    /// Future Native callers must account for their other private retained files
    /// in the same unchanged ceiling; this candidate does not do their replay.
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
            "live packed append batch bound",
        )?;
        require(
            bytes(&records)?
                .len()
                .checked_add(bytes(&self.manifest.tail)?.len())
                .is_some_and(|n| n <= MAX_BYTES),
            "live packed staged record byte capacity",
        )?;
        let mut proposed = self.manifest.clone();
        let mut objects = Vec::new();
        for record in records {
            proposed.head = next_head(proposed.head, proposed.count, record)?;
            proposed.count = proposed
                .count
                .checked_add(1)
                .ok_or("live packed record count overflow")?;
            proposed.tail.push(record.clone());
            if proposed.tail.len() == PAGE {
                let page = Page {
                    format: super::super::FORMAT.into(),
                    scope: proposed.scope.clone(),
                    first: proposed
                        .count
                        .checked_sub(PAGE as u64)
                        .ok_or("live packed page offset")?,
                    previous: proposed.previous_page,
                    records: std::mem::take(&mut proposed.tail),
                };
                let raw = bytes(&page)?;
                let first = proposed.complete.first().unwrap_or(&page);
                let context = PackedPageContextCandidateV1 {
                    scope: proposed.scope.clone(),
                    first_record: first.first,
                    previous_page: first.previous,
                    previous_pack: proposed.packs.last().map(|p| p.encoded.hash),
                };
                let overhead = header(&context, 1)?.len()
                    + usize::from(context.previous_page.is_none()) * 32
                    + usize::from(context.previous_pack.is_none()) * 32;
                require(
                    raw.len()
                        .checked_add(4)
                        .and_then(|size| size.checked_add(overhead))
                        .is_some_and(|size| size <= MAX_BYTES),
                    "live packed single complete page capacity",
                )?;
                let existing = proposed
                    .complete
                    .iter()
                    .map(|p| bytes(p).map(|b| b.len() + 4))
                    .collect::<Result<Vec<_>>>()?;
                let fits = existing
                    .into_iter()
                    .try_fold(
                        header(&context, proposed.complete.len() + 1)?.len(),
                        |size, n| size.checked_add(n),
                    )
                    .and_then(|size| size.checked_add(raw.len() + 4))
                    .is_some_and(|size| size <= MAX_BYTES);
                if !fits {
                    Self::flush(&mut proposed, &mut objects)?;
                }
                proposed.previous_page = Some(Hash(Sha256::digest(&raw).into()));
                proposed.complete.push(page);
                if proposed.complete.len() == MAX_PACKED_PAGES_CANDIDATE {
                    Self::flush(&mut proposed, &mut objects)?;
                }
            }
        }
        let raw = bytes(&proposed)?;
        let pending = bytes(&Publication {
            expected_head,
            manifest: &proposed,
            objects: &objects,
        })?;
        let (files, retained) = usage(&self.dir)?;
        let mut new_files = 2usize; // complete pending payload and commit manifest
        let mut extra_bytes = (pending.len() as u64)
            .checked_add(raw.len() as u64)
            .ok_or("live packed publication overflow")?;
        for object in &objects {
            let data = STANDARD
                .decode(&object.encoded_b64)
                .map_err(|e| e.to_string())?;
            require(
                STANDARD.encode(&data) == object.encoded_b64,
                "live packed pending encoding differs",
            )?;
            let path = self.dir.join(OBJECTS).join(name(object.pack.encoded.hash));
            if exists(&path)? {
                require(
                    *keystore::private_read(&path, MAX_BYTES)? == data,
                    "live packed immutable object differs",
                )?;
            } else {
                new_files = new_files
                    .checked_add(1)
                    .ok_or("live packed publication count overflow")?;
                extra_bytes = extra_bytes
                    .checked_add(data.len() as u64)
                    .ok_or("live packed publication byte overflow")?;
            }
        }
        require(
            files
                .checked_add(new_files)
                .and_then(|n| n.checked_add(external_files))
                .is_some_and(|n| n <= history::MAX_FILES)
                && retained
                    .checked_add(extra_bytes)
                    .and_then(|n| n.checked_add(external_bytes))
                    .is_some_and(|n| n <= history::MAX_ARCHIVE_BYTES),
            "live packed total publication capacity",
        )?;
        let outcome = (|| {
            keystore::private_create(&self.dir.join(PENDING), &pending)?;
            #[cfg(test)]
            if self.interruption == Some(0) {
                return Err("injected after live packed pending".into());
            }
            for object in &objects {
                let data = STANDARD
                    .decode(&object.encoded_b64)
                    .map_err(|e| e.to_string())?;
                let path = self.dir.join(OBJECTS).join(name(object.pack.encoded.hash));
                if exists(&path)? {
                    require(
                        *keystore::private_read(&path, MAX_BYTES)? == data,
                        "live packed immutable object differs",
                    )?;
                    File::open(&path).map_err(err)?.sync_all().map_err(err)?;
                    File::open(self.dir.join(OBJECTS))
                        .map_err(err)?
                        .sync_all()
                        .map_err(err)?;
                } else {
                    keystore::private_create(&path, &data)?;
                }
            }
            #[cfg(test)]
            if self.interruption == Some(1) {
                return Err("injected after live packed objects".into());
            }
            keystore::private_create(&self.dir.join(COMMIT), &raw)?;
            fs::rename(self.dir.join(COMMIT), self.dir.join(MANIFEST)).map_err(err)?;
            File::open(&self.dir)
                .map_err(err)?
                .sync_all()
                .map_err(err)?;
            #[cfg(test)]
            if self.interruption == Some(2) {
                return Err("injected after live packed manifest".into());
            }
            // Every original byte remains in complete lossless packs or the
            // full manifest tail. Only the now redundant wrapper is removed.
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

#[cfg(test)]
mod tests;
