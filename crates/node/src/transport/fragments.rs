use super::*;
use std::collections::BTreeMap;
const CHUNK: usize = 1024 * 1024;
record!(Fragment {object:Id => 0,whole_sha256:Id => 1,total:u32 => 2,offset:u32 => 3,bytes:Blob => 4});
record!(PartialManifest {object:Id => 0,whole_sha256:Id => 1,total:u32 => 2});
impl Fragment {
    pub fn validate(&self) -> Result<()> {
        let total = self.total as usize;
        let offset = self.offset as usize;
        ensure!(
            total > 0
                && total <= rld_protocol::MAX_CAPSULE
                && offset < total
                && offset % CHUNK == 0
                && self.bytes.0.len() == CHUNK.min(total - offset),
            "fragment bounds/size"
        );
        Ok(())
    }
}
impl Spool {
    fn usage(&self) -> Result<BTreeMap<Id, u64>> {
        let mut sizes = BTreeMap::new();
        for entry in fs::read_dir(self.root.join("packets"))? {
            let entry = entry?;
            ensure!(entry.file_type()?.is_file(), "unexpected packet entry");
            let id = Id::parse(
                entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .context("packet filename")?,
            )?;
            sizes.insert(id, entry.metadata()?.len());
        }
        for entry in fs::read_dir(self.root.join("incoming"))? {
            let entry = entry?;
            ensure!(entry.file_type()?.is_dir(), "unexpected fragment entry");
            let p: PartialManifest =
                decode(&read_bounded(&entry.path().join("MANIFEST"), 512)?, 512)?;
            ensure!(
                p.total > 0
                    && p.total as usize <= rld_protocol::MAX_CAPSULE
                    && entry.file_name().to_str() == Some(&p.object.to_string()),
                "partial manifest binding"
            );
            if let Some(size) = sizes.get(&p.object) {
                ensure!(*size == p.total as u64, "partial/complete size mismatch")
            }
            sizes.insert(p.object, p.total as u64);
        }
        Ok(sizes)
    }
    fn metadata_bytes(&self) -> Result<u64> {
        let mut total = 1024u64;
        for name in ["receipts", "receipts/objects", "accepted"] {
            for entry in fs::read_dir(self.root.join(name))? {
                let e = entry?;
                if name == "receipts" && e.file_name() == "objects" {
                    ensure!(e.file_type()?.is_dir(), "receipt objects directory");
                    continue;
                }
                ensure!(e.file_type()?.is_file(), "unexpected custody metadata");
                total = total
                    .checked_add(e.metadata()?.len())
                    .context("metadata byte overflow")?;
            }
        }
        Ok(total)
    }
    pub(super) fn metadata_capacity(&self, additional: usize) -> Result<()> {
        let packets = self.usage()?.values().try_fold(0u64, |n, v| {
            n.checked_add(*v).context("custody size overflow")
        })?;
        let current = self.metadata_bytes()?;
        ensure!(
            packets
                .checked_add(current)
                .and_then(|n| n.checked_add(additional as u64))
                .is_some_and(|n| n <= self.max_bytes),
            "custody evidence/receipt byte capacity exhausted"
        );
        Ok(())
    }
    pub(super) fn capacity(&self, id: Id, total: usize) -> Result<()> {
        let sizes = self.usage()?;
        if let Some(old) = sizes.get(&id) {
            ensure!(*old == total as u64, "existing custody size");
            return Ok(());
        }
        let used = sizes.values().try_fold(self.metadata_bytes()?, |n, v| {
            n.checked_add(*v).context("spool byte overflow")
        })?;
        ensure!(
            sizes.len() < self.max_objects
                && used
                    .checked_add(total as u64)
                    .is_some_and(|n| n <= self.max_bytes),
            "whole/partial custody capacity exhausted"
        );
        Ok(())
    }
    pub fn retain_fragment(&self, f: &Fragment) -> Result<Option<Id>> {
        f.validate()?;
        if self.packet(f.object).exists() {
            let bytes = read_bounded(&self.packet(f.object), rld_protocol::MAX_CAPSULE)?;
            ensure!(
                Id::digest(&bytes) == f.whole_sha256
                    && bytes.len() == f.total as usize
                    && bytes[f.offset as usize..f.offset as usize + f.bytes.0.len()] == f.bytes.0,
                "fragment differs from retained complete object"
            );
            File::open(self.packet(f.object))?.sync_all()?;
            sync_dir(&self.root.join("packets"))?;
            return Ok(Some(f.object));
        }
        self.capacity(f.object, f.total as usize)?;
        let dir = self.root.join("incoming").join(f.object.to_string());
        let m = PartialManifest {
            object: f.object,
            whole_sha256: f.whole_sha256,
            total: f.total,
        };
        if dir.exists() {
            let old: PartialManifest = decode(&read_bounded(&dir.join("MANIFEST"), 512)?, 512)?;
            ensure!(old == m, "mixed fragment commitment")
        } else {
            fs::create_dir(&dir)?;
            private_create(&dir.join("MANIFEST"), &encode(&m))?;
            sync_dir(&dir)?;
            sync_dir(dir.parent().context("incoming parent")?)?;
        }
        let chunk = dir.join(format!("{:08}.chunk", f.offset));
        if chunk.exists() {
            ensure!(
                read_bounded(&chunk, CHUNK)? == f.bytes.0,
                "changed/corrupt retained fragment"
            );
            File::open(&chunk)?.sync_all()?;
        } else {
            private_create(&chunk, &f.bytes.0)?;
        }
        sync_dir(&dir)?;
        let total = f.total as usize;
        let mut complete = Vec::with_capacity(total);
        for offset in (0..total).step_by(CHUNK) {
            let path = dir.join(format!("{offset:08}.chunk"));
            if !path.exists() {
                return Ok(None);
            }
            let bytes = read_bounded(&path, CHUNK)?;
            ensure!(
                bytes.len() == CHUNK.min(total - offset),
                "retained fragment size"
            );
            complete.extend_from_slice(&bytes);
        }
        ensure!(
            Id::digest(&complete) == f.whole_sha256,
            "whole object hash mismatch; preserve damaged fragments"
        );
        let d: Dispatch = decode(&complete, rld_protocol::MAX_CAPSULE)?;
        ensure!(
            dispatch_id(self.currency, &d) == f.object,
            "whole object identity"
        );
        self.retain(&d)?;
        // Exact complete bytes are now fsynced. These are redundant carriage pieces,
        // not unresolved ledger or owner evidence.
        for offset in (0..total).step_by(CHUNK) {
            fs::remove_file(dir.join(format!("{offset:08}.chunk")))?;
        }
        fs::remove_file(dir.join("MANIFEST"))?;
        fs::remove_dir(&dir)?;
        sync_dir(&self.root.join("incoming"))?;
        Ok(Some(f.object))
    }
    pub(super) fn pending_fragments(&self, peer: Id, cursor: usize) -> Result<Vec<Fragment>> {
        let mut packets = Vec::new();
        for (id, d) in self.packets()? {
            if !self.confirmed(peer, id)? {
                packets.push((id, d));
            }
        }
        if packets.is_empty() {
            return Ok(vec![]);
        }
        let n = packets.len();
        packets.rotate_left(cursor % n);
        let mut out = Vec::new();
        let mut budget = 4096;
        for (id, d) in packets {
            let bytes = encode(&d);
            let count = bytes.len().div_ceil(CHUNK);
            for step in 0..count {
                let chunk = (cursor / n + step) % count;
                let offset = chunk * CHUNK;
                let f = Fragment {
                    object: id,
                    whole_sha256: Id::digest(&bytes),
                    total: u32::try_from(bytes.len())?,
                    offset: u32::try_from(offset)?,
                    bytes: Blob(bytes[offset..(offset + CHUNK).min(bytes.len())].to_vec()),
                };
                let size = encode(&f).len();
                if out.len() < 16 && budget + size < rld_protocol::MAX_CAPSULE {
                    budget += size;
                    out.push(f);
                } else {
                    break;
                }
            }
            if out.len() == 16 || budget + CHUNK >= rld_protocol::MAX_CAPSULE {
                break;
            }
        }
        Ok(out)
    }
    fn confirmed(&self, peer: Id, id: Id) -> Result<bool> {
        let path = self.root.join("receipts").join(format!("{peer}-{id}.cbor"));
        if !path.exists() {
            return Ok(false);
        }
        let reference: Id = decode(&read_bounded(&path, 128)?, 128)?;
        let bytes = read_bounded(
            &self
                .root
                .join("receipts/objects")
                .join(format!("{reference}.cbor")),
            rld_protocol::MAX_CAPSULE + 8192,
        )?;
        ensure!(
            Id::digest(&bytes) == reference,
            "retained acknowledgment object hash"
        );
        let (exchange, ack): (Exchange, Acknowledgment) =
            decode(&bytes, rld_protocol::MAX_CAPSULE + 8192)?;
        let identity = Peer {
            identity: peer,
            domain: Id::ZERO,
            endpoint: String::new(),
            certificate_pem: String::new(),
            certificate_sha256: Id::ZERO,
        };
        verify_ack(self.currency, &identity, &exchange, &ack)?;
        ensure!(ack.retained.contains(&id), "receipt does not cover packet");
        Ok(true)
    }
}
