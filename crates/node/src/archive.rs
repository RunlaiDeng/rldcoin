//! Complete immutable event segments. Segment hashes describe storage, never
//! consensus authority. Cold startup still replays every event from genesis
//! and requires the separately retained exact latest head.
use crate::store::{Frame, MAX_RECORD, Tip, private_create, read_bounded, sync_dir};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, decode, encode},
    record,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_SEGMENT: u64 = 256 * 1024 * 1024;
const MAX_EVENTS: u64 = 64;
const HOT_EVENTS: u64 = 128;
const MAGIC: &[u8] = b"RLD-EVENT-SEGMENT-1\n";
record!(Segment{format:String => 0,first:u64 => 1,last:u64 => 2,previous:Id => 3,head:Id => 4,bytes:u64 => 5,digest:Id => 6,source:Tip => 7});
record!(Seal{segment:Segment => 0});
pub(crate) struct Archive {
    root: PathBuf,
    segments: BTreeMap<u64, Segment>,
    observations: BTreeMap<u64, Id>,
}
fn frame_path(root: &Path, n: u64) -> PathBuf {
    root.join("events").join(format!("{n:020}.cbor"))
}
fn seal_path(root: &Path, first: u64) -> PathBuf {
    root.join("archive").join(format!("{first:020}.cbor"))
}
fn pack_path(root: &Path, s: &Segment) -> PathBuf {
    root.join("archive/objects")
        .join(format!("{}.pack", s.digest))
}
fn check_segment(s: &Segment, tip: &Tip) -> Result<()> {
    ensure!(
        s.format == "RLD-EVENT-SEGMENT-1"
            && s.first > 0
            && s.last >= s.first
            && s.last - s.first < MAX_EVENTS
            && s.last <= s.source.generation
            && s.source.generation <= tip.generation
            && s.bytes <= MAX_SEGMENT
            && s.bytes >= MAGIC.len() as u64,
        "archive segment bounds/binding"
    );
    Ok(())
}
fn stream(root: &Path, s: &Segment, mut f: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
    let mut input = File::open(pack_path(root, s))?;
    ensure!(input.metadata()?.len() == s.bytes, "archive segment length");
    let mut h = Sha256::new();
    let mut magic = vec![0; MAGIC.len()];
    input.read_exact(&mut magic)?;
    ensure!(magic == MAGIC, "archive segment profile");
    h.update(&magic);
    let mut total = MAGIC.len() as u64;
    let mut previous = s.previous;
    for n in s.first..=s.last {
        let mut length = [0; 8];
        input.read_exact(&mut length)?;
        h.update(length);
        let size = u64::from_be_bytes(length);
        ensure!(
            size > 0
                && size <= MAX_RECORD as u64
                && total
                    .checked_add(8)
                    .and_then(|v| v.checked_add(size))
                    .is_some_and(|v| v <= s.bytes),
            "archive frame bound"
        );
        let mut bytes = vec![0; usize::try_from(size)?];
        input.read_exact(&mut bytes)?;
        h.update(&bytes);
        total += 8 + size;
        let event: Frame = decode(&bytes, MAX_RECORD)?;
        ensure!(
            event.generation == n && event.previous == previous,
            "archive frame chain"
        );
        previous = Id::digest(&bytes);
        f(n, &bytes)?;
    }
    let mut extra = [0];
    ensure!(
        total == s.bytes
            && input.read(&mut extra)? == 0
            && Id(h.finalize().into()) == s.digest
            && previous == s.head,
        "archive segment digest/tail"
    );
    Ok(())
}
impl Archive {
    pub(crate) fn open(root: &Path, tip: &Tip, recover: bool) -> Result<Self> {
        // Absence is the original unsegmented storage format, not an upgrade
        // of any monetary state or signer. Directory creation is storage-only.
        fs::create_dir_all(root.join("archive/objects"))?;
        let pending = root.join("ARCHIVING");
        ensure!(
            !pending.exists() || recover,
            "interrupted archive publication: explicit node recover required"
        );
        let mut segments = BTreeMap::new();
        for e in fs::read_dir(root.join("archive"))? {
            let e = e?;
            if e.file_name() == "objects" {
                ensure!(e.file_type()?.is_dir(), "archive objects entry");
                continue;
            }
            ensure!(e.file_type()?.is_file(), "archive manifest entry");
            let seal: Seal = decode(&read_bounded(&e.path(), 2048)?, 2048)?;
            let s = seal.segment;
            check_segment(&s, tip)?;
            ensure!(
                e.path() == seal_path(root, s.first) && segments.insert(s.first, s).is_none(),
                "archive manifest identity"
            );
        }
        let mut next = 1u64;
        for s in segments.values() {
            ensure!(s.first == next, "archive gap/overlap");
            next = s
                .last
                .checked_add(1)
                .context("archive position exhaustion")?;
        }
        if pending.exists() {
            let p: Seal = decode(&read_bounded(&pending, 2048)?, 2048)?;
            check_segment(&p.segment, tip)?;
            // Complete packs can be recovered after full native replay. A
            // damaged/incomplete pack remains untouched alongside hot originals.
            stream(root, &p.segment, |n, bytes| {
                let path = frame_path(root, n);
                if path.exists() {
                    ensure!(
                        read_bounded(&path, MAX_RECORD)? == bytes,
                        "archive source changed"
                    );
                }
                Ok(())
            })?;
            if let Some(old) = segments.get(&p.segment.first) {
                ensure!(old == &p.segment, "changed pending archive");
            } else {
                ensure!(p.segment.first == next, "pending archive gap");
                segments.insert(p.segment.first, p.segment);
            }
        }
        let mut observations = BTreeMap::new();
        for segment in segments.values() {
            if let Some(old) = observations.insert(segment.source.generation, segment.source.head) {
                ensure!(
                    old == segment.source.head,
                    "contradictory archive source observations"
                );
            }
        }
        Ok(Self {
            root: root.into(),
            segments,
            observations,
        })
    }
    pub(crate) fn check_source_observation(&self, n: u64, head: Id) -> Result<()> {
        if let Some(expected) = self.observations.get(&n) {
            ensure!(
                *expected == head,
                "archive source head is not in the authenticated journal"
            );
        }
        Ok(())
    }
    pub(crate) fn archived_last(&self) -> u64 {
        self.segments.values().next_back().map_or(0, |s| s.last)
    }
    pub(crate) fn walk(&self, mut apply: impl FnMut(u64, &[u8]) -> Result<()>) -> Result<()> {
        for s in self.segments.values() {
            stream(&self.root, s, |n, bytes| {
                let path = frame_path(&self.root, n);
                if path.exists() {
                    ensure!(
                        read_bounded(&path, MAX_RECORD)? == bytes,
                        "changed duplicate archived event"
                    );
                }
                apply(n, bytes)
            })?;
        }
        Ok(())
    }
    pub(crate) fn finish_recovery(&mut self) -> Result<()> {
        let pending = self.root.join("ARCHIVING");
        if !pending.exists() {
            return Ok(());
        }
        let p: Seal = decode(&read_bounded(&pending, 2048)?, 2048)?;
        let s = &p.segment;
        ensure!(
            self.segments.get(&s.first) == Some(s),
            "unreplayed pending archive"
        );
        let seal = seal_path(&self.root, s.first);
        if !seal.exists() {
            private_create(&seal, &encode(&p))?;
            sync_dir(&self.root.join("archive"))?;
        }
        self.remove_redundant(s)?;
        fs::remove_file(pending)?;
        sync_dir(&self.root)
    }
    fn remove_redundant(&self, s: &Segment) -> Result<()> {
        // Verify the durable replacement bytes before removing a redundant
        // original. Native replay has separately authenticated monetary state.
        stream(&self.root, s, |_, _| Ok(()))?;
        stream(&self.root, s, |n, bytes| {
            let path = frame_path(&self.root, n);
            if path.exists() {
                ensure!(
                    read_bounded(&path, MAX_RECORD)? == bytes,
                    "changed original during archival"
                );
                fs::remove_file(path)?;
            }
            Ok(())
        })?;
        sync_dir(&self.root.join("events"))
    }
    pub(crate) fn rotate(&mut self, tip: &Tip, heads: &BTreeMap<u64, Id>) -> Result<bool> {
        ensure!(
            !self.root.join("PENDING").exists() && !self.root.join("ARCHIVING").exists(),
            "unfinished storage transaction"
        );
        let first = self
            .archived_last()
            .checked_add(1)
            .context("archive position exhaustion")?;
        let eligible = tip.generation.saturating_sub(HOT_EVENTS);
        if first > eligible {
            return Ok(false);
        }
        let mut frames = Vec::new();
        let mut length = MAGIC.len() as u64;
        let mut previous = None;
        let mut head = Id::ZERO;
        let mut last = first;
        for n in first
            ..=eligible.min(
                first
                    .checked_add(MAX_EVENTS - 1)
                    .context("archive sequence overflow")?,
            )
        {
            let bytes = read_bounded(&frame_path(&self.root, n), MAX_RECORD)?;
            ensure!(
                heads.get(&n) == Some(&Id::digest(&bytes)),
                "archive source differs from independently replayed event"
            );
            let new = length
                .checked_add(8 + bytes.len() as u64)
                .context("archive size overflow")?;
            if new > MAX_SEGMENT {
                break;
            }
            let frame: Frame = decode(&bytes, MAX_RECORD)?;
            ensure!(
                frame.generation == n && previous.is_none_or(|_| frame.previous == head),
                "archive source chain"
            );
            if previous.is_none() {
                previous = Some(frame.previous)
            }
            head = Id::digest(&bytes);
            length = new;
            last = n;
            frames.push(bytes);
        }
        // Archive maintenance must not invalidate an otherwise admissible
        // native event (MAX_RECORD is larger than this storage segment bound).
        // Keep that exact loose event and all later frames; never skip a chain
        // position, enlarge the segment or delete evidence to make progress.
        if frames.is_empty() {
            return Ok(false);
        }
        let mut h = Sha256::new();
        h.update(MAGIC);
        for bytes in &frames {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes)
        }
        let s = Segment {
            format: "RLD-EVENT-SEGMENT-1".into(),
            first,
            last,
            previous: previous.context("segment predecessor")?,
            head,
            bytes: length,
            digest: Id(h.finalize().into()),
            source: tip.clone(),
        };
        let expected_previous = self
            .segments
            .values()
            .next_back()
            .map_or(Id::ZERO, |s| s.head);
        ensure!(
            s.previous == expected_previous && heads.get(&s.last) == Some(&s.head),
            "archive commitment differs from retained authenticated prefix"
        );
        let pack = pack_path(&self.root, &s);
        let seal = Seal { segment: s.clone() };
        // An orphaned complete pack is never authority; check its exact bytes
        // before reuse. A partially written orphan refuses without overwrite.
        if pack.exists() {
            stream(&self.root, &s, |_, _| Ok(()))?;
        } else {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&pack)?;
            f.write_all(MAGIC)?;
            for bytes in &frames {
                f.write_all(&(bytes.len() as u64).to_be_bytes())?;
                f.write_all(bytes)?;
            }
            f.sync_all()?;
            sync_dir(pack.parent().context("pack parent")?)?;
        }
        stream(&self.root, &s, |_, _| Ok(()))?;
        private_create(&self.root.join("ARCHIVING"), &encode(&seal))?;
        sync_dir(&self.root)?;
        private_create(&seal_path(&self.root, first), &encode(&seal))?;
        sync_dir(&self.root.join("archive"))?;
        self.segments.insert(first, s.clone());
        self.observations.insert(tip.generation, tip.head);
        self.remove_redundant(&s)?;
        fs::remove_file(self.root.join("ARCHIVING"))?;
        sync_dir(&self.root)?;
        Ok(true)
    }
}
