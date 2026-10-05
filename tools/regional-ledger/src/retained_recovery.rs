//! Read-only complete pending inspection, then explicitly native-authorized
//! recovery of one retained signer response. Ledger streams cannot use this.
use super::*;
pub(crate) struct RecoveryView<T> {
    dir: PathBuf,
    publication: Publication<T>,
}
impl<T: Clone + Serialize + DeserializeOwned> RecoveryView<T> {
    pub(crate) fn head(&self) -> Hash {
        self.publication.manifest.head
    }
    /// Visit the exact complete proposed stream. Missing newly sealed bytes may
    /// come ONLY from its durable pending payload, never an orphan/cache/ledger.
    pub(crate) fn visit(&self, consume: impl FnMut(&T, bool) -> Result<()>) -> Result<()> {
        self.inspect(consume).map(|_| ())
    }
    fn inspect(&self, mut consume: impl FnMut(&T, bool) -> Result<()>) -> Result<Manifest<T>> {
        let m = &self.publication.manifest;
        require(
            m.format == FORMAT
                && m.count > 0
                && m.pages.len() <= history::MAX_FILES
                && m.tail.len() < PAGE
                && m.count / PAGE as u64 == m.pages.len() as u64
                && m.count % PAGE as u64 == m.tail.len() as u64,
            "retained response complete proposed page/count shape",
        )?;
        let old_count = m.count - 1;
        let old_pages =
            usize::try_from(old_count / PAGE as u64).map_err(|_| "recovery page count")?;
        require(
            self.publication.pages.len() == m.pages.len() - old_pages
                && self.publication.pages.len() <= 1,
            "retained response exactly one append/new page",
        )?;
        let mut index = 0u64;
        let mut head = m.scope.initial()?;
        let mut previous = None;
        let mut old_tail = Vec::new();
        let mut one = |record: &T| -> Result<()> {
            if index == old_count {
                require(
                    head == self.publication.expected_head,
                    "retained response old prefix differs from caller head",
                )?;
            } else if index >= (old_pages * PAGE) as u64 {
                old_tail.push(record.clone());
            }
            consume(record, index == old_count)?;
            head = next_head(head, index, record)?;
            index = index
                .checked_add(1)
                .ok_or("recovery record count overflow")?;
            Ok(())
        };
        for (number, reference) in m.pages.iter().enumerate() {
            require(
                reference.bytes > 0 && reference.bytes <= MAX_BYTES,
                "recovery page bound",
            )?;
            let raw = if number >= old_pages {
                bytes(
                    self.publication
                        .pages
                        .get(number - old_pages)
                        .ok_or("complete pending page missing")?,
                )?
            } else {
                keystore::private_read(
                    &self.dir.join(OBJECTS).join(page_name(reference.hash)),
                    MAX_BYTES,
                )?
                .to_vec()
            };
            require(
                raw.len() == reference.bytes && Hash(Sha256::digest(&raw).into()) == reference.hash,
                "retained response exact complete page digest/length",
            )?;
            let page: Page<T> = decode(&raw)?;
            require(
                page.format == FORMAT
                    && page.scope == m.scope
                    && page.first == (number * PAGE) as u64
                    && page.previous == previous
                    && page.records.len() == PAGE,
                "retained response complete page order/domain",
            )?;
            for record in &page.records {
                one(record)?;
            }
            previous = Some(reference.hash);
        }
        for record in &m.tail {
            one(record)?;
        }
        require(
            index == m.count && head == m.head,
            "retained response complete proposed head/count",
        )?;
        Ok(Manifest {
            format: FORMAT.into(),
            scope: m.scope.clone(),
            pages: m.pages[..old_pages].to_vec(),
            tail: old_tail,
            count: old_count,
            head: self.publication.expected_head,
        })
    }
}
impl<T: Clone + Serialize + DeserializeOwned> Stream<T> {
    /// All structural/capacity checks precede the native callback. The callback
    /// must fully authenticate/execute every original record and exact caller
    /// request/transition before it returns. Only then can durable bytes publish.
    pub(crate) fn recover_one_authenticated<R>(
        dir: &Path,
        scope: &Scope,
        caller_head: Hash,
        external_files: usize,
        external_bytes: u64,
        authenticate: impl FnOnce(&RecoveryView<T>) -> Result<R>,
    ) -> Result<(Self, R)> {
        private_dir(dir)?;
        let guard = lock(dir)?;
        root_inventory(dir)?;
        require(
            matches!(&scope.purpose, Purpose::BftSigner(_)),
            "only explicit signer pending response recovery",
        )?;
        let current_raw = keystore::private_read(&dir.join(MANIFEST), MAX_BYTES)?;
        let current: Manifest<T> = decode(&current_raw)?;
        let pending_raw = keystore::private_read(&dir.join(PENDING), MAX_BYTES)?;
        let publication: Publication<T> = decode(&pending_raw)?;
        require(
            current.format == FORMAT
                && current.scope == *scope
                && publication.manifest.scope == *scope
                && publication.expected_head == caller_head,
            "retained response exact immutable scope/separate caller head",
        )?;
        let view = RecoveryView {
            dir: dir.into(),
            publication,
        };
        let old = view.inspect(|_, _| Ok(()))?;
        let proposed_raw = bytes(&view.publication.manifest)?;
        require(
            *current_raw == bytes(&old)? || *current_raw == proposed_raw,
            "retained current manifest is neither exact old nor proposed publication",
        )?;
        let commit_exists = exists(&dir.join(COMMIT))?;
        if commit_exists {
            require(
                *keystore::private_read(&dir.join(COMMIT), MAX_BYTES)? == proposed_raw,
                "retained commit differs from complete pending publication",
            )?;
        }
        let archive = dir.join(OBJECTS);
        let (mut count, mut total) = usage(&archive)?;
        // When current already equals proposed and no commit remains, recovery
        // creates no commit. Count only actual files plus required publication.
        let needs_commit = *current_raw != proposed_raw;
        let retained_or_planned_commit = needs_commit || commit_exists;
        count = count
            .checked_add(3 + usize::from(retained_or_planned_commit))
            .and_then(|n| n.checked_add(external_files))
            .ok_or("recovery file count overflow")?;
        total = total
            .checked_add(current_raw.len() as u64)
            .and_then(|n| n.checked_add(pending_raw.len() as u64))
            .and_then(|n| {
                n.checked_add(if retained_or_planned_commit {
                    proposed_raw.len() as u64
                } else {
                    0
                })
            })
            .and_then(|n| n.checked_add(external_bytes))
            .ok_or("recovery archive byte overflow")?;
        for page in &view.publication.pages {
            let raw = bytes(page)?;
            let hash = Hash(Sha256::digest(&raw).into());
            let path = archive.join(page_name(hash));
            if exists(&path)? {
                require(
                    *keystore::private_read(&path, MAX_BYTES)? == raw,
                    "retained immutable pending page changed",
                )?;
            } else {
                count = count.checked_add(1).ok_or("recovery page count overflow")?;
                total = total
                    .checked_add(raw.len() as u64)
                    .ok_or("recovery page byte overflow")?;
            }
        }
        require(
            count <= history::MAX_FILES && total <= history::MAX_ARCHIVE_BYTES,
            "retained recovery full archive capacity; retain residue",
        )?;
        // Nothing above or inside the read-only callback can promote custody.
        let authenticated = authenticate(&view)?;
        for page in &view.publication.pages {
            let raw = bytes(page)?;
            let path = archive.join(page_name(Hash(Sha256::digest(&raw).into())));
            if exists(&path)? {
                require(
                    *keystore::private_read(&path, MAX_BYTES)? == raw,
                    "retained page changed during recovery",
                )?;
                File::open(&path).map_err(err)?.sync_all().map_err(err)?;
                File::open(&archive).map_err(err)?.sync_all().map_err(err)?;
            } else {
                keystore::private_create(&path, &raw)?;
            }
        }
        if needs_commit {
            if !commit_exists {
                keystore::private_create(&dir.join(COMMIT), &proposed_raw)?;
            }
            fs::rename(dir.join(COMMIT), dir.join(MANIFEST)).map_err(err)?;
        } else {
            File::open(dir.join(MANIFEST))
                .map_err(err)?
                .sync_all()
                .map_err(err)?;
        }
        File::open(dir).map_err(err)?.sync_all().map_err(err)?;
        if exists(&dir.join(COMMIT))? {
            fs::remove_file(dir.join(COMMIT)).map_err(err)?;
        }
        // Original unique response is now in the exact durable page/tail;
        // remove only redundant fully completed publication wrappers.
        fs::remove_file(dir.join(PENDING)).map_err(err)?;
        File::open(dir).map_err(err)?.sync_all().map_err(err)?;
        let stream = Self {
            dir: dir.into(),
            _lock: guard,
            manifest: view.publication.manifest,
            healthy: true,
            _type: PhantomData,
            #[cfg(test)]
            interruption: None,
        };
        stream.visit(stream.storage_head(), |_| Ok(()))?;
        Ok((stream, authenticated))
    }
}

/// Adversarial fixture only: rebuild exact canonical hashes while changing the
/// last signature. No production caller or private key enters this path.
#[cfg(test)]
pub(crate) fn rewrite_last_pending_for_fixture<T: Clone + Serialize + DeserializeOwned>(
    dir: &Path,
    mutate: impl FnOnce(&mut T),
) {
    let mut p: Publication<T> =
        decode(&keystore::private_read(&dir.join(PENDING), MAX_BYTES).unwrap()).unwrap();
    assert_eq!(p.pages.len(), 1);
    assert!(p.manifest.tail.is_empty());
    let page = p.pages.last_mut().unwrap();
    mutate(page.records.last_mut().unwrap());
    p.manifest.head = next_head(
        p.expected_head,
        p.manifest.count - 1,
        page.records.last().unwrap(),
    )
    .unwrap();
    let page_raw = bytes(page).unwrap();
    let hash = Hash(Sha256::digest(&page_raw).into());
    let previous_hash = p.manifest.pages.last().unwrap().hash;
    *p.manifest.pages.last_mut().unwrap() = history::Reference {
        hash,
        bytes: page_raw.len(),
    };
    if exists(&dir.join(OBJECTS).join(page_name(previous_hash))).unwrap() {
        keystore::private_create(&dir.join(OBJECTS).join(page_name(hash)), &page_raw).unwrap();
    }
    let current: Manifest<T> =
        decode(&keystore::private_read(&dir.join(MANIFEST), MAX_BYTES).unwrap()).unwrap();
    if current.count == p.manifest.count {
        fs::write(dir.join(MANIFEST), bytes(&p.manifest).unwrap()).unwrap();
    }
    if exists(&dir.join(COMMIT)).unwrap() {
        fs::write(dir.join(COMMIT), bytes(&p.manifest).unwrap()).unwrap();
    }
    fs::write(dir.join(PENDING), bytes(&p).unwrap()).unwrap();
}
