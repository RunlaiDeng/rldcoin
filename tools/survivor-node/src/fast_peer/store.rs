//! Append-only data custody, never ledger/signing authority. Queue capacity
//! reserves exact returned-response space until local durable acknowledgment.
use super::{
    codec::{self, Packet},
    Config,
};
use crate::{
    fast_payment::ensure,
    fast_retainer::{io, parent, private, sync, Reader},
    kernel::{Hash, Result},
};
use fs2::FileExt;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const LIMIT: usize = 32 * 1024 * 1024;
const ACK_SPACE: usize = 414;
enum Target {
    Head(Hash),
    Last {
        prior: Hash,
        packet_or_message: Hash,
    },
}
#[derive(Clone)]
pub struct Item {
    pub packet: Packet,
    pub at: u64,
    pub received: bool,
    pub response: Option<Vec<u8>>,
}
pub struct Custody {
    path: PathBuf,
    file: File,
    prefix: Vec<u8>,
    chain: Hash,
    local: Hash,
    pub head: Hash,
    clock: u64,
    index: u64,
    pub items: BTreeMap<Hash, Item>,
    pub order: Vec<Hash>,
    reserved: usize,
    poisoned: bool,
}
fn head(raw: &[u8]) -> Hash {
    codec::hash("BOX-HEADER", raw)
}
fn file(path: &Path) -> Result<File> {
    private(parent(path)?, false)?;
    private(path, true)?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(io)?;
    FileExt::try_lock_exclusive(&f).map_err(|_| "RESOURCE_WAIT peer custody writer")?;
    Ok(f)
}
impl Custody {
    pub fn ready(&self) -> bool {
        !self.poisoned
    }
    pub fn create(
        path: &Path,
        config: &Config,
        local: Hash,
        material: Hash,
        now: u64,
    ) -> Result<Self> {
        private(parent(path)?, false)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(path).map_err(io)?;
        FileExt::try_lock_exclusive(&f).map_err(|_| "RESOURCE_WAIT peer custody writer")?;
        let mut h = b"RLDFPEER".to_vec();
        h.extend([0, 1, 0, 1]);
        h.extend(config.chain.0);
        h.extend(local);
        h.extend(material);
        h.extend(config.digest()?);
        h.extend(now.to_be_bytes());
        f.write_all(&h).map_err(io)?;
        sync(&f, path)?;
        let expected = head(&h);
        Self::load(
            path,
            f,
            config,
            local,
            material,
            Target::Head(expected),
            now,
        )
    }
    pub fn open(
        path: &Path,
        c: &Config,
        local: Hash,
        material: Hash,
        expected: Hash,
        now: u64,
    ) -> Result<Self> {
        Self::load(
            path,
            file(path)?,
            c,
            local,
            material,
            Target::Head(expected),
            now,
        )
    }
    pub fn recover(
        path: &Path,
        c: &Config,
        local: Hash,
        material: Hash,
        prior: Hash,
        packet_or_message: Hash,
        now: u64,
    ) -> Result<Hash> {
        let mut retained = Self::load(
            path,
            file(path)?,
            c,
            local,
            material,
            Target::Last {
                prior,
                packet_or_message,
            },
            now,
        )?;
        retained.check()?;
        sync(&retained.file, path)?;
        retained.check()?;
        Ok(retained.head)
    }
    fn load(
        path: &Path,
        mut file: File,
        c: &Config,
        local: Hash,
        material: Hash,
        target: Target,
        now: u64,
    ) -> Result<Self> {
        ensure(
            file.metadata().map_err(io)?.len() <= LIMIT as u64,
            "RESOURCE_WAIT peer custody limit",
        )?;
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut prefix = vec![];
        Read::by_ref(&mut file)
            .take(LIMIT as u64 + 1)
            .read_to_end(&mut prefix)
            .map_err(io)?;
        ensure(prefix.len() <= LIMIT, "RESOURCE_WAIT peer custody grew")?;
        let mut r = Reader {
            raw: &prefix,
            at: 0,
        };
        ensure(
            r.take(8)? == b"RLDFPEER" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED peer custody",
        )?;
        ensure(
            r.hash()? == c.chain.0
                && r.hash()? == local
                && r.hash()? == material
                && r.hash()? == c.digest()?,
            "INVALID peer custody trust binding",
        )?;
        let mut clock = r.u64()?;
        ensure(clock <= now, "CLOCK_WAIT peer custody creation")?;
        let mut h = head(&prefix[..r.at]);
        let mut index = 0;
        let mut items = BTreeMap::<Hash, Item>::new();
        let mut order = vec![];
        let mut reserved = 0;
        let mut last = None;
        while r.at < prefix.len() {
            let n = r.u32()? as usize;
            ensure(
                (85..=85 + codec::MAX_PACKET).contains(&n),
                "INVALID peer custody record bound",
            )?;
            let b = r.take(n)?;
            let mut p = Reader { raw: b, at: 0 };
            let i = p.u64()?;
            ensure(
                i == index + 1 && p.hash()? == h,
                "INVALID peer custody record order",
            )?;
            let time = p.u64()?;
            ensure(
                time >= clock && time <= now,
                "CLOCK_WAIT peer custody record",
            )?;
            let kind = p.take(1)?[0];
            let size = p.u32()? as usize;
            ensure(
                size <= codec::MAX_PACKET && n == 85 + size,
                "INVALID peer custody payload length",
            )?;
            let body = p.take(size)?;
            let next = p.hash()?;
            ensure(
                next == codec::hash("BOX-RECORD", &b[..n - 32]),
                "INVALID peer custody digest",
            )?;
            let last_id = if kind == 1 || kind == 2 {
                let packet = Packet::decode(body, c.chain.0)?;
                let id = packet.id;
                ensure(
                    items.len() < 2048 && !items.contains_key(&packet.id),
                    "RESOURCE_WAIT peer custody packet count/duplicate",
                )?;
                let received = kind == 2;
                Self::admission(c, local, &packet, received)?;
                if !received {
                    reserved += ACK_SPACE;
                }
                order.push(packet.id);
                items.insert(
                    packet.id,
                    Item {
                        packet,
                        at: time,
                        received,
                        response: None,
                    },
                );
                id
            } else if kind == 3 {
                ensure(body.len() == 325, "INVALID peer custody response size")?;
                let id: Hash = body[..32].try_into().unwrap();
                let item = items
                    .get_mut(&id)
                    .ok_or("INVALID peer response without queue")?;
                ensure(
                    !item.received && item.response.is_none(),
                    "INVALID peer repeated/nonlocal response",
                )?;
                codec::check_response(
                    &body[32..],
                    c.chain.0,
                    local,
                    item.packet.destination,
                    id,
                    None,
                )?;
                item.response = Some(body[32..].to_vec());
                reserved -= ACK_SPACE;
                id
            } else {
                return Err("UNSUPPORTED peer custody record kind".into());
            };
            ensure(
                r.at.checked_add(reserved).is_some_and(|n| n <= LIMIT),
                "RESOURCE_WAIT peer reserved response budget",
            )?;
            last = Some((h, last_id, items[&last_id].packet.raw[101..133].to_vec()));
            h = next;
            index = i;
            clock = time;
        }
        match target {
            Target::Head(expected) => ensure(
                h == expected,
                "INVALID independently pinned peer custody head",
            )?,
            Target::Last {
                prior,
                packet_or_message,
            } => ensure(
                last.is_some_and(|(p, id, message)| {
                    p == prior && (id == packet_or_message || message == packet_or_message)
                }),
                "INVALID exact last peer custody recovery binding",
            )?,
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            prefix,
            chain: c.chain.0,
            local,
            head: h,
            clock,
            index,
            items,
            order,
            reserved,
            poisoned: false,
        })
    }
    fn admission(c: &Config, local: Hash, p: &Packet, received: bool) -> Result<()> {
        ensure(
            if received {
                p.destination == local && c.peers.iter().any(|n| n.key.0 == p.sender)
            } else {
                p.sender == local && c.peers.iter().any(|n| n.key.0 == p.destination)
            },
            "INVALID peer custody admitted direction",
        )
    }
    pub fn check(&mut self) -> Result<()> {
        ensure(
            !self.poisoned,
            "RESOURCE_WAIT peer custody restart required",
        )?;
        self.poisoned = true;
        private(parent(&self.path)?, false)?;
        private(&self.path, true)?;
        let a = fs::symlink_metadata(&self.path).map_err(io)?;
        let b = self.file.metadata().map_err(io)?;
        ensure(
            a.len() == self.prefix.len() as u64 && a.len() == b.len(),
            "INVALID peer custody changed length",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure(
                a.dev() == b.dev() && a.ino() == b.ino(),
                "INVALID peer custody replaced file",
            )?;
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut chunk = [0; 65536];
        for c in self.prefix.chunks(chunk.len()) {
            self.file.read_exact(&mut chunk[..c.len()]).map_err(io)?;
            ensure(
                c == &chunk[..c.len()],
                "INVALID peer custody changed prefix",
            )?;
        }
        self.poisoned = false;
        Ok(())
    }
    fn append(&mut self, kind: u8, payload: &[u8], now: u64, reserved_after: usize) -> Result<()> {
        self.check()?;
        ensure(now >= self.clock, "CLOCK_WAIT peer custody rollback")?;
        let mut b = (self.index + 1).to_be_bytes().to_vec();
        b.extend(self.head);
        b.extend(now.to_be_bytes());
        b.push(kind);
        b.extend((payload.len() as u32).to_be_bytes());
        b.extend(payload);
        let next = codec::hash("BOX-RECORD", &b);
        b.extend(next);
        let raw = [(b.len() as u32).to_be_bytes().as_slice(), &b].concat();
        ensure(
            self.prefix
                .len()
                .checked_add(raw.len() + reserved_after)
                .is_some_and(|n| n <= LIMIT),
            "RESOURCE_WAIT peer custody response reservation",
        )?;
        self.poisoned = true;
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&raw))
            .map_err(io)?;
        sync(&self.file, &self.path)?;
        self.prefix.extend(raw);
        self.head = next;
        self.index += 1;
        self.clock = now;
        self.reserved = reserved_after;
        self.poisoned = false;
        self.check()
    }
    pub fn keep(&mut self, c: &Config, packet: &Packet, received: bool, now: u64) -> Result<Hash> {
        self.check()?;
        ensure(now >= self.clock, "CLOCK_WAIT peer custody rollback")?;
        let checked = Packet::decode(&packet.raw, self.chain)?;
        Self::admission(c, self.local, &checked, received)?;
        if let Some(old) = self.items.get(&checked.id) {
            ensure(
                old.received == received && old.packet.raw == checked.raw,
                "INVALID peer custody changed duplicate",
            )?;
            sync(&self.file, &self.path)?;
            self.check()?;
            return Ok(self.head);
        }
        ensure(
            self.items.len() < 2048,
            "RESOURCE_WAIT peer custody packet count",
        )?;
        let reserved = self.reserved + if received { 0 } else { ACK_SPACE };
        self.append(if received { 2 } else { 1 }, &checked.raw, now, reserved)?;
        self.order.push(checked.id);
        self.items.insert(
            checked.id,
            Item {
                packet: checked,
                at: now,
                received,
                response: None,
            },
        );
        Ok(self.head)
    }
    pub fn acknowledge(&mut self, id: Hash, response: &[u8], now: u64) -> Result<()> {
        self.check()?;
        let item = self.items.get(&id).ok_or("MISSING peer queued packet")?;
        ensure(!item.received, "INVALID peer response role")?;
        codec::check_response(
            response,
            self.chain,
            self.local,
            item.packet.destination,
            id,
            None,
        )?;
        if let Some(old) = &item.response {
            ensure(old == response, "INVALID peer response replacement")?;
            sync(&self.file, &self.path)?;
            return Ok(());
        }
        let body = [id.as_slice(), response].concat();
        self.append(3, &body, now, self.reserved - ACK_SPACE)?;
        self.items.get_mut(&id).unwrap().response = Some(response.to_vec());
        Ok(())
    }
    pub fn get(&mut self, id: Hash) -> Result<Item> {
        self.check()?;
        let i = self.items.get(&id).ok_or("MISSING peer packet")?.clone();
        Packet::decode(&i.packet.raw, self.chain)?;
        Ok(i)
    }
}
