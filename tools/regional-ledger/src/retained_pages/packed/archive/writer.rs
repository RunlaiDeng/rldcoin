//! One-pass fresh archive construction. No append, resume or Native authority.
use super::*;

/// Holds only one bounded complete-page group; complete packs go directly to
/// the locked private target. Any failed retain poisons this writer permanently.
pub struct LosslessArchiveWriterCandidate<T> {
    dir: PathBuf,
    guard: File,
    builder: Builder,
    group: Vec<Vec<u8>>,
    previous: Option<Hash>,
    held: usize,
    failed: bool,
    _type: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> LosslessArchiveWriterCandidate<T> {
    pub fn begin(dir: &Path, independently_scope: Scope) -> Result<Self> {
        let head = independently_scope.initial()?;
        private_dir(dir.parent().ok_or("packed archive parent missing")?)?;
        require(!exists(dir)?, "packed archive requires absent fresh target")?;
        make_dir(dir)?;
        keystore::private_create(&dir.join("LOCK"), b"")?;
        let guard = lock(dir)?;
        make_dir(&dir.join(OBJECTS))?;
        keystore::private_create(
            &dir.join(MARKER),
            &bytes(&(LOSSLESS_FORMAT, &independently_scope))?,
        )?;
        Ok(Self {
            dir: dir.into(),
            guard,
            builder: Builder {
                context: PackedPageContextCandidateV1 {
                    scope: independently_scope,
                    first_record: 0,
                    previous_page: None,
                    previous_pack: None,
                },
                head,
                count: 0,
                packs: vec![],
                originals: vec![],
                lossless: true,
            },
            group: vec![],
            previous: None,
            held: 0,
            failed: false,
            _type: PhantomData,
        })
    }

    /// Retain an exact canonical original page, including all sixteen records.
    /// Validate the incoming page before publishing any preceding pending group.
    pub fn retain_complete_page(&mut self, raw: Vec<u8>) -> Result<()> {
        require(
            !self.failed,
            "failed packed writer; retain original residue",
        )?;
        self.failed = true;
        require(
            !raw.is_empty() && raw.len() <= MAX_BYTES,
            "packed staged complete page byte capacity",
        )?;
        let page: Page<T> = decode(&raw)?;
        require(
            page.format == super::super::super::FORMAT
                && page.scope == self.builder.context.scope
                && page.first == self.builder.count
                && page.previous == self.previous
                && page.records.len() == PAGE,
            "packed writer complete original page domain/order/count",
        )?;
        let mut head = self.builder.head;
        let mut count = self.builder.count;
        for record in &page.records {
            head = next_head(head, count, record)?;
            count = count.checked_add(1).ok_or("packed seal record overflow")?;
        }
        let overhead = header(&self.builder.context, 1)?.len();
        // Both predecessor options are present after the first pack. Reserve
        // those bytes even when the current header starts at the origin.
        let maximum_overhead = overhead
            + usize::from(self.builder.context.previous_page.is_none()) * 32
            + usize::from(self.builder.context.previous_pack.is_none()) * 32;
        require(
            raw.len()
                .checked_add(4)
                .and_then(|n| n.checked_add(maximum_overhead))
                .is_some_and(|n| n <= MAX_BYTES),
            "packed staged object byte capacity",
        )?;
        if !self.group.is_empty()
            && (self.group.len() == MAX_PACKED_PAGES_CANDIDATE
                || self
                    .held
                    .checked_add(4)
                    .and_then(|n| n.checked_add(raw.len()))
                    .and_then(|n| n.checked_add(maximum_overhead))
                    .is_none_or(|n| n > MAX_BYTES))
        {
            self.flush()?;
        }
        self.held = self
            .held
            .checked_add(4)
            .and_then(|n| n.checked_add(raw.len()))
            .ok_or("packed staged byte overflow")?;
        self.previous = Some(Hash(sha2::Sha256::digest(&raw).into()));
        self.group.push(raw);
        self.builder.head = head;
        self.builder.count = count;
        self.failed = false;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.builder.flush::<T>(&self.dir, &mut self.group)?;
        self.held = 0;
        Ok(())
    }

    /// The producer supplies its separately computed complete record head only
    /// after generation. No writer observation supplies Native ending authority.
    pub fn finish(self, independently_expected_head: Hash) -> Result<PackedArchiveCandidate<T>> {
        self.finish_inner(independently_expected_head, None)
    }

    fn finish_inner(
        mut self,
        expected: Hash,
        interrupt: Option<u8>,
    ) -> Result<PackedArchiveCandidate<T>> {
        require(
            !self.failed,
            "failed packed writer; retain original residue",
        )?;
        self.flush()?;
        if interrupt == Some(0) {
            return Err("injected after retained complete pack".into());
        }
        require(
            self.builder.head == expected,
            "packed archive independently expected complete head differs",
        )?;
        let manifest = Manifest {
            format: LOSSLESS_FORMAT.into(),
            scope: self.builder.context.scope,
            packs: self.builder.packs,
            count: self.builder.count,
            head: self.builder.head,
            original_packs: self.builder.originals,
        };
        let raw = bytes(&manifest)?;
        preflight(&self.dir, 1, raw.len() as u64)?;
        keystore::private_create(&self.dir.join(MANIFEST), &raw)?;
        if interrupt == Some(1) {
            return Err("injected after retained complete manifest".into());
        }
        fs::remove_file(self.dir.join(MARKER)).map_err(err)?;
        File::open(&self.dir)
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        let archive = PackedArchiveCandidate {
            dir: self.dir,
            _lock: self.guard,
            manifest,
            _type: PhantomData,
        };
        archive.visit(expected, |_| Ok(()))?;
        Ok(archive)
    }

    #[cfg(test)]
    pub(super) fn pending_candidate(&self) -> (usize, usize, usize) {
        (self.group.len(), self.held, self.builder.packs.len())
    }

    #[cfg(test)]
    pub(super) fn finish_interrupted_candidate(
        self,
        head: Hash,
        boundary: u8,
    ) -> Result<PackedArchiveCandidate<T>> {
        self.finish_inner(head, Some(boundary))
    }
}
