//! One bounded original pack/page at a time; no Native execution initializer.
use super::*;
use std::collections::VecDeque;

pub(crate) struct Records<'a, T> {
    stream: &'a AppendablePackedStreamCandidate<T>,
    expected: Hash,
    pack: usize,
    page: usize,
    index: u64,
    head: Hash,
    previous: Option<Hash>,
    previous_pack: Option<Hash>,
    tail: bool,
    finished: bool,
    ready: VecDeque<T>,
}
impl<'a, T: Clone + Serialize + DeserializeOwned> Records<'a, T> {
    pub(super) fn new(
        stream: &'a AppendablePackedStreamCandidate<T>,
        expected: Hash,
    ) -> Result<Self> {
        Ok(Self {
            stream,
            expected,
            pack: 0,
            page: 0,
            index: 0,
            head: stream.manifest.scope.initial()?,
            previous: None,
            previous_pack: None,
            tail: false,
            finished: false,
            ready: VecDeque::new(),
        })
    }
    fn load(&mut self) -> Result<()> {
        require(
            self.stream.healthy
                && !exists(&self.stream.dir.join(PENDING))?
                && !exists(&self.stream.dir.join(COMMIT))?,
            "live packed cursor has incomplete publication",
        )?;
        require(
            *keystore::private_read(&self.stream.dir.join(MANIFEST), MAX_BYTES)?
                == bytes(&self.stream.manifest)?,
            "live packed cursor manifest changed",
        )?;
        if let Some(pack) = self.stream.manifest.packs.get(self.pack) {
            let context = PackedPageContextCandidateV1 {
                scope: self.stream.manifest.scope.clone(),
                first_record: self.index,
                previous_page: self.previous,
                previous_pack: self.previous_pack,
            };
            let raw = keystore::private_read(
                &self.stream.dir.join(OBJECTS).join(name(pack.encoded.hash)),
                MAX_BYTES,
            )?;
            let verified = lossless::verify_lossless_complete_pack_candidate::<T>(
                &context,
                &pack.original,
                &pack.encoded,
                &raw,
            )?;
            let mut offset = header(&context, verified.complete.complete_pages.len())?.len();
            for _ in &verified.complete.complete_pages {
                let length = u32::from_be_bytes(
                    take(&verified.original_pack, &mut offset, 4)?
                        .try_into()
                        .unwrap(),
                ) as usize;
                let page: Page<T> = decode(take(&verified.original_pack, &mut offset, length)?)?;
                visit_page(
                    &page,
                    &context.scope,
                    &mut self.index,
                    &mut self.head,
                    &mut self.previous,
                    &mut |record| {
                        self.ready.push_back(record.clone());
                        Ok(())
                    },
                )?;
            }
            require(
                offset == verified.original_pack.len()
                    && self.index == verified.complete.next_record
                    && self.previous == Some(verified.complete.last_page),
                "live packed cursor complete pack differs",
            )?;
            self.previous_pack = Some(pack.encoded.hash);
            self.pack += 1;
        } else if let Some(page) = self.stream.manifest.complete.get(self.page) {
            visit_page(
                page,
                &self.stream.manifest.scope,
                &mut self.index,
                &mut self.head,
                &mut self.previous,
                &mut |record| {
                    self.ready.push_back(record.clone());
                    Ok(())
                },
            )?;
            self.page += 1;
        } else if !self.tail {
            for record in &self.stream.manifest.tail {
                self.head = next_head(self.head, self.index, record)?;
                self.index = self
                    .index
                    .checked_add(1)
                    .ok_or("live packed cursor count overflow")?;
                self.ready.push_back(record.clone());
            }
            self.tail = true;
        } else {
            require(
                self.index == self.stream.manifest.count
                    && self.head == self.expected
                    && self.head == self.stream.manifest.head
                    && self.previous == self.stream.manifest.previous_page,
                "live packed cursor final head/count differs",
            )?;
            self.finished = true;
        }
        Ok(())
    }
}
impl<T: Clone + Serialize + DeserializeOwned> Iterator for Records<'_, T> {
    type Item = Result<T>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.ready.is_empty() && !self.finished {
            if let Err(error) = self.load() {
                self.finished = true;
                return Some(Err(error));
            }
        }
        self.ready.pop_front().map(Ok)
    }
}
