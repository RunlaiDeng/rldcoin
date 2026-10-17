//! Bounded independent contact custody. Data custody never authorizes money.
use crate::{
    contact::{peer_id, Frame, Packet},
    kernel::{Hash, Result},
};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    path::Path,
};
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT carriage {e}")
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn h(x: Vec<u8>) -> Result<Hash> {
    x.try_into()
        .map_err(|_| "INVALID_ENCODING custody hash".into())
}
fn class(kind: u8) -> u8 {
    match kind {
        3 => 1,
        2 => 2,
        9 => 3,
        8 => 4,
        _ => 0,
    }
}
#[derive(Clone, Copy)]
pub struct Budget {
    pub packets: usize,
    pub bytes: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            packets: 4096,
            bytes: 256 * 1024 * 1024,
        }
    }
}
pub struct Carriage {
    pub(crate) db: Connection,
    _lease: File,
    pub(crate) chain: Hash,
    pub(crate) identity: Hash,
    budget: Budget,
}
impl Carriage {
    pub fn open(root: &Path, chain: Hash, identity: Hash, budget: Budget) -> Result<Self> {
        ensure(
            crate::kernel::valid_point(identity),
            "INVALID_CRYPTO contact key",
        )?;
        if !root.exists() {
            fs::create_dir(root).map_err(err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(err)?;
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(root.join("writer.lock")).map_err(err)?;
        lease
            .try_lock_exclusive()
            .map_err(|_| "RESOURCE_WAIT carriage writer")?;
        let path = root.join("carriage.sqlite3");
        drop(options.open(&path).map_err(err)?);
        let db = Connection::open(path).map_err(err)?;
        let page: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(err)?;
        ensure(
            page > 0 && budget.bytes >= 32768,
            "RESOURCE_WAIT custody database budget",
        )?;
        let pages = budget.bytes / (page as usize);
        let actual: i64 = db
            .query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))
            .map_err(err)?;
        ensure(
            actual > 0 && actual as usize <= pages,
            "RESOURCE_WAIT existing custody database",
        )?;
        db.execute_batch("PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=EXTRA;PRAGMA fullfsync=ON;CREATE TABLE IF NOT EXISTS identity (one INTEGER PRIMARY KEY CHECK(one=1),chain BLOB NOT NULL,owner BLOB NOT NULL,sequence BLOB NOT NULL,neighbor_cursor BLOB, class_cursor INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS packets (id BLOB PRIMARY KEY,origin BLOB NOT NULL,sequence BLOB NOT NULL,raw BLOB NOT NULL,incoming BLOB,kind INTEGER NOT NULL,done INTEGER NOT NULL,processed INTEGER NOT NULL,UNIQUE(origin,sequence));CREATE TABLE IF NOT EXISTS receipts (packet BLOB PRIMARY KEY,raw BLOB NOT NULL);CREATE TABLE IF NOT EXISTS cursors (class INTEGER PRIMARY KEY,id BLOB NOT NULL);CREATE TABLE IF NOT EXISTS hop_receipts (packet BLOB NOT NULL,sender BLOB NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(packet,sender));CREATE TABLE IF NOT EXISTS equivocation (origin BLOB NOT NULL,sequence BLOB NOT NULL,first BLOB NOT NULL,second BLOB NOT NULL,PRIMARY KEY(origin,sequence));").map_err(err)?;
        let old: Option<(Vec<u8>, Vec<u8>)> = db
            .query_row("SELECT chain,owner FROM identity WHERE one=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(err)?;
        if let Some((c, k)) = old {
            ensure(c == chain && k == identity, "WRONG_CHAIN contact store")?
        } else {
            let count: i64 = db
                .query_row("SELECT count(*) FROM packets", [], |r| r.get(0))
                .map_err(err)?;
            ensure(count == 0, "INVALID_ENCODING missing contact binding")?;
            db.execute(
                "INSERT INTO identity VALUES(1,?1,?2,?3,NULL,0)",
                params![
                    chain.as_slice(),
                    identity.as_slice(),
                    0u128.to_be_bytes().as_slice()
                ],
            )
            .map_err(err)?;
        }
        File::open(root).and_then(|f| f.sync_all()).map_err(err)?;
        File::open(root.parent().ok_or("INVALID_ENCODING custody parent")?)
            .and_then(|f| f.sync_all())
            .map_err(err)?;
        let s = Self {
            db,
            _lease: lease,
            chain,
            identity,
            budget,
        };
        s.offline_open()?;
        let mut stmt =
            s.db.prepare("SELECT id,origin,sequence,raw,kind FROM packets")
                .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(r) = rows.next().map_err(err)? {
            let raw: Vec<u8> = r.get(3).map_err(err)?;
            let p = Packet::decode(&raw, chain)?;
            ensure(
                h(r.get(0).map_err(err)?)? == p.id
                    && h(r.get(1).map_err(err)?)? == p.origin
                    && r.get::<_, Vec<u8>>(2).map_err(err)? == p.sequence.to_be_bytes()
                    && r.get::<_, u8>(4).map_err(err)? == p.kind,
                "INVALID_ENCODING custody index",
            )?;
        }
        drop(rows);
        drop(stmt);
        let mut stmt =
            s.db.prepare("SELECT packet,raw FROM receipts")
                .map_err(err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(err)?;
        for row in rows {
            let (id, raw) = row.map_err(err)?;
            let p = s
                .packet(h(id)?)?
                .ok_or("INVALID_ENCODING receipt without original")?;
            let f = Frame::decode(&raw, chain)?;
            ensure(f.discharges(&p), "INVALID_CRYPTO retained receipt")?;
        }
        drop(stmt);
        let mut stmt =
            s.db.prepare("SELECT packet,sender,raw FROM hop_receipts")
                .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(r) = rows.next().map_err(err)? {
            let id = h(r.get(0).map_err(err)?)?;
            let sender = h(r.get(1).map_err(err)?)?;
            let raw: Vec<u8> = r.get(2).map_err(err)?;
            let f = Frame::decode(&raw, chain)?;
            let p = s
                .packet(id)?
                .ok_or("INVALID_ENCODING retained hop packet")?;
            ensure(
                f.kind == 3
                    && f.sender == sender
                    && f.packet_id == Some(id)
                    && f.receiver == peer_id(identity)
                    && matches!(f.result, Some(0 | 1))
                    && (f.result != Some(1) || f.discharges(&p)),
                "INVALID_CRYPTO retained hop observation",
            )?;
        }
        drop(rows);
        drop(stmt);
        let unjustified:i64=s.db.query_row("SELECT count(*) FROM packets WHERE done<>0 AND NOT EXISTS(SELECT 1 FROM receipts WHERE packet=packets.id)",[],|r|r.get(0)).map_err(err)?;
        ensure(
            unjustified == 0,
            "INVALID_CRYPTO suppression without destination receipt",
        )?;
        s.capacity(0, 0)?;
        s.candidate_identities()?;
        Ok(s)
    }
    pub(crate) fn capacity(&self, extra: usize, count: usize) -> Result<()> {
        let pages: i64 = self
            .db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(err)?;
        let size: i64 = self
            .db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(err)?;
        ensure(
            pages >= 0
                && size > 0
                && (pages as usize)
                    .checked_mul(size as usize)
                    .is_some_and(|n| n <= self.budget.bytes),
            "RESOURCE_WAIT physical custody capacity",
        )?;
        let (n, size): (i64, i64) = self
            .db
            .query_row(
                "SELECT count(*),coalesce(sum(length(raw)+160),0) FROM packets",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        let other:i64=self.db.query_row("SELECT coalesce((SELECT sum(length(raw)+64) FROM receipts),0)+coalesce((SELECT sum(length(raw)+96) FROM hop_receipts),0)+coalesce((SELECT sum(length(raw)+96) FROM offline_out),0)+(SELECT count(*)*64 FROM candidates)+(SELECT count(*)*128 FROM equivocation)+(SELECT count(*)*64 FROM cursors)+256",[],|r|r.get(0)).map_err(err)?;
        ensure(
            n >= 0
                && size >= 0
                && other >= 0
                && (n as usize)
                    .checked_add(count)
                    .is_some_and(|n| n <= self.budget.packets)
                && (size as usize)
                    .checked_add(other as usize)
                    .and_then(|n| n.checked_add(extra))
                    .is_some_and(|n| n <= self.budget.bytes),
            "RESOURCE_WAIT custody capacity",
        )
    }
    pub fn packet(&self, id: Hash) -> Result<Option<Packet>> {
        let b: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM packets WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        b.map(|x| Packet::decode(&x, self.chain)).transpose()
    }
    pub fn originate(
        &mut self,
        key: &SigningKey,
        destination: Hash,
        kind: u8,
        payload: &[u8],
    ) -> Result<Packet> {
        self.compact_completed()?;
        ensure(
            key.verifying_key().to_bytes() == self.identity,
            "INVALID_CRYPTO origin key",
        )?;
        let raw: Vec<u8> = self
            .db
            .query_row("SELECT sequence FROM identity WHERE one=1", [], |r| {
                r.get(0)
            })
            .map_err(err)?;
        let seq = u128::from_be_bytes(
            raw.try_into()
                .map_err(|_| "INVALID_ENCODING origin sequence")?,
        );
        let next = seq
            .checked_add(1)
            .ok_or("RESOURCE_WAIT sequence exhausted")?;
        let packet = Packet::sign(self.chain, key, destination, next, kind, payload)?;
        self.capacity(packet.raw.len() + 160, 1)?;
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "UPDATE identity SET sequence=?1 WHERE one=1",
            [next.to_be_bytes().as_slice()],
        )
        .map_err(err)?;
        tx.execute(
            "INSERT INTO packets VALUES(?1,?2,?3,?4,NULL,?5,0,0)",
            params![
                packet.id.as_slice(),
                self.identity.as_slice(),
                next.to_be_bytes().as_slice(),
                packet.raw,
                kind
            ],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(packet)
    }
    /// Caller supplies independently admitted sender and adapter/session binding.
    /// Receipt signing occurs only after exact authenticated bytes are committed.
    pub fn receive(
        &mut self,
        raw: &[u8],
        sender: Hash,
        challenge: Hash,
        offline: bool,
        key: &SigningKey,
    ) -> Result<Option<Frame>> {
        ensure(
            key.verifying_key().to_bytes() == self.identity,
            "INVALID_CRYPTO custodian key",
        )?;
        let f = Frame::decode(raw, self.chain)?;
        let p = f.authenticate_delivery(sender, peer_id(self.identity), challenge, offline)?;
        self.compact_completed()?;
        if p.kind == 9 {
            let r = Frame::decode(&p.payload, self.chain)?;
            if let Some(original) =
                self.packet(r.packet_id.ok_or("INVALID_ENCODING returned packet")?)?
            {
                ensure(
                    p.destination == peer_id(original.origin),
                    "INVALID_CRYPTO return destination",
                )?;
                self.retain_destination_receipt(&original, &r)?;
            }
            // A different return relay need not possess the original packet.
            // Keep a bounded control copy, without a receipt-of-receipt promise.
            if p.destination != peer_id(self.identity)
                && self.packet(p.id)?.is_none()
                && self.capacity(p.raw.len() + 160, 1).is_ok()
            {
                self.db
                    .execute(
                        "INSERT OR IGNORE INTO packets VALUES(?1,?2,?3,?4,?5,9,0,0)",
                        params![
                            p.id.as_slice(),
                            p.origin.as_slice(),
                            p.sequence.to_be_bytes().as_slice(),
                            p.raw,
                            sender.as_slice()
                        ],
                    )
                    .map_err(err)?;
            }
            return Ok(None);
        }
        if let Some(old) = self.packet(p.id)? {
            ensure(old.raw == p.raw, "INVALID_ENCODING custody collision")?;
        } else {
            let same: Option<Vec<u8>> = self
                .db
                .query_row(
                    "SELECT id FROM packets WHERE origin=?1 AND sequence=?2",
                    params![p.origin.as_slice(), p.sequence.to_be_bytes().as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(err)?;
            if let Some(first) = same {
                self.capacity(128, 0)?;
                self.db
                    .execute(
                        "INSERT OR IGNORE INTO equivocation VALUES(?1,?2,?3,?4)",
                        params![
                            p.origin.as_slice(),
                            p.sequence.to_be_bytes().as_slice(),
                            first,
                            p.id.as_slice()
                        ],
                    )
                    .map_err(err)?;
                return Err("INVALID_CRYPTO origin sequence equivocation".into());
            }
            if self.capacity(p.raw.len() + 160, 1).is_err() {
                return Ok(Some(Frame::receipt(self.chain, key, &f, 2)?));
            }
            self.db
                .execute(
                    "INSERT INTO packets VALUES(?1,?2,?3,?4,?5,?6,0,0)",
                    params![
                        p.id.as_slice(),
                        p.origin.as_slice(),
                        p.sequence.to_be_bytes().as_slice(),
                        p.raw,
                        sender.as_slice(),
                        p.kind
                    ],
                )
                .map_err(err)?;
        }
        let code = if p.destination == peer_id(self.identity) {
            1
        } else {
            0
        };
        let receipt = Frame::receipt(self.chain, key, &f, code)?;
        if code == 1 {
            self.retain_destination_receipt(p, &receipt)?;
        }
        Ok(Some(receipt))
    }
    pub fn retain_destination_receipt(&mut self, p: &Packet, f: &Frame) -> Result<()> {
        let p = Packet::decode(&p.raw, self.chain)?;
        let f = Frame::decode(&f.raw, self.chain)?;
        ensure(f.discharges(&p), "INVALID_CRYPTO destination receipt")?;
        ensure(
            self.packet(p.id)?.is_some(),
            "MISSING_HISTORY original packet",
        )?;
        let old: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM receipts WHERE packet=?1",
                [p.id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if old.is_some() {
            return Ok(());
        }
        self.capacity(f.raw.len() + 64, 0)?;
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "INSERT INTO receipts VALUES(?1,?2)",
            params![p.id.as_slice(), f.raw],
        )
        .map_err(err)?;
        tx.execute("UPDATE packets SET done=1 WHERE id=?1", [p.id.as_slice()])
            .map_err(err)?;
        tx.commit().map_err(err)?;
        Ok(())
    }
    /// One durable round-robin neighbor/class step, at most 16 packets. Cursor
    /// advances before a connection attempt; failures cannot pin the schedule.
    pub fn prepare(
        &mut self,
        neighbors: &[Hash],
        suppressed: &BTreeSet<(Hash, Hash)>,
    ) -> Result<Option<(Hash, Vec<Packet>)>> {
        ensure(
            neighbors.iter().all(|k| crate::kernel::valid_point(*k)),
            "INVALID_CRYPTO configured neighbor",
        )?;
        if neighbors.is_empty() {
            return Ok(None);
        }
        let mut keys = neighbors.to_vec();
        keys.sort_unstable();
        keys.dedup();
        let (last, start): (Option<Vec<u8>>, u8) = self
            .db
            .query_row(
                "SELECT neighbor_cursor,class_cursor FROM identity WHERE one=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        let last = last.map(h).transpose()?;
        let peer = keys
            .iter()
            .find(|k| last.is_none_or(|x| **k > x))
            .copied()
            .unwrap_or(keys[0]);
        let mut result = Vec::new();
        let mut chosen = start;
        for delta in 0..5 {
            let c = (start + delta) % 5;
            let cursor: Option<Vec<u8>> = self
                .db
                .query_row("SELECT id FROM cursors WHERE class=?1", [c], |r| r.get(0))
                .optional()
                .map_err(err)?;
            let cursor = cursor.map(h).transpose()?.unwrap_or([0; 32]);
            let mut stmt = self
                .db
                .prepare("SELECT raw,incoming FROM packets WHERE done=0 ORDER BY id<=?1,id")
                .map_err(err)?;
            let rows = stmt
                .query_map([cursor.as_slice()], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Option<Vec<u8>>>(1)?))
                })
                .map_err(err)?;
            for row in rows {
                let (raw, incoming) = row.map_err(err)?;
                let p = Packet::decode(&raw, self.chain)?;
                if p.destination == peer_id(self.identity) {
                    continue;
                }
                if class(p.kind) != c
                    || incoming.as_deref() == Some(peer.as_slice())
                    || suppressed.contains(&(peer, p.id))
                {
                    continue;
                }
                let direct = keys.iter().find(|k| peer_id(**k) == p.destination);
                if direct.is_some_and(|k| *k != peer) {
                    continue;
                }
                result.push(p);
                if result.len() == 16 {
                    break;
                }
            }
            if !result.is_empty() {
                chosen = c;
                break;
            }
        }
        let tx = self.db.transaction().map_err(err)?;
        tx.execute(
            "UPDATE identity SET neighbor_cursor=?1,class_cursor=?2 WHERE one=1",
            params![peer.as_slice(), (chosen + 1) % 5],
        )
        .map_err(err)?;
        if let Some(p) = result.last() {
            tx.execute(
                "INSERT OR REPLACE INTO cursors VALUES(?1,?2)",
                params![chosen, p.id.as_slice()],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(Some((peer, result)))
    }
    pub fn pending(&self) -> Result<Vec<Packet>> {
        let cursor: Option<Vec<u8>> = self
            .db
            .query_row("SELECT id FROM cursors WHERE class=5", [], |r| r.get(0))
            .optional()
            .map_err(err)?;
        let cursor = cursor.map(h).transpose()?.unwrap_or([0; 32]);
        let mut stmt = self
            .db
            .prepare("SELECT raw FROM packets WHERE processed=0 ORDER BY id<=?1,id LIMIT 32")
            .map_err(err)?;
        let rows = stmt
            .query_map([cursor.as_slice()], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        let result: Vec<Packet> = rows
            .map(|r| Packet::decode(&r.map_err(err)?, self.chain))
            .collect::<Result<_>>()?;
        if let Some(p) = result.last() {
            self.db
                .execute(
                    "INSERT OR REPLACE INTO cursors VALUES(5,?1)",
                    [p.id.as_slice()],
                )
                .map_err(err)?;
        }
        Ok(result)
    }
    pub fn retain_hop_receipt(&self, id: Hash, f: &Frame) -> Result<()> {
        let f = Frame::decode(&f.raw, self.chain)?;
        ensure(
            f.kind == 3
                && f.packet_id == Some(id)
                && f.receiver == peer_id(self.identity)
                && matches!(f.result, Some(0 | 1)),
            "INVALID_CRYPTO hop observation",
        )?;
        let p = self.packet(id)?.ok_or("MISSING_HISTORY hop packet")?;
        if f.result == Some(1) {
            ensure(f.discharges(&p), "INVALID_CRYPTO hop destination")?;
        }
        self.capacity(f.raw.len() + 96, 0)?;
        self.db
            .execute(
                "INSERT OR REPLACE INTO hop_receipts VALUES(?1,?2,?3)",
                params![id.as_slice(), f.sender.as_slice(), f.raw],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn processed(&self, id: Hash) -> Result<()> {
        self.db
            .execute(
                "UPDATE packets SET processed=1 WHERE id=?1",
                [id.as_slice()],
            )
            .map_err(err)?;
        Ok(())
    }
}

impl Carriage {
    pub fn transaction_observation(&self, raw: &[u8]) -> Result<serde_json::Value> {
        let tx = crate::kernel::decode_tx(raw, self.chain)?;
        let mut stmt = self
            .db
            .prepare("SELECT raw FROM packets WHERE kind=2 ORDER BY id")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        let mut observations = Vec::new();
        let mut level = 0;
        while let Some(row) = rows.next().map_err(err)? {
            let p = Packet::decode(&row.get::<_, Vec<u8>>(0).map_err(err)?, self.chain)?;
            if crate::kernel::decode_tx(&p.payload, self.chain)?.id != tx.id {
                continue;
            }
            level = level.max(1);
            observations.push(serde_json::json!({"packet_id":hex::encode(p.id),"destination":hex::encode(p.destination),"state":"QUEUED"}));
            let mut receipts=self.db.prepare("SELECT raw FROM receipts WHERE packet=?1 UNION SELECT raw FROM hop_receipts WHERE packet=?1").map_err(err)?;
            let rs = receipts
                .query_map([p.id.as_slice()], |r| r.get::<_, Vec<u8>>(0))
                .map_err(err)?;
            for r in rs {
                let f = Frame::decode(&r.map_err(err)?, self.chain)?;
                let state = if f.discharges(&p) {
                    level = 3;
                    "DESTINATION_CUSTODY"
                } else {
                    level = level.max(2);
                    "HOP_CUSTODY"
                };
                observations.push(serde_json::json!({"packet_id":hex::encode(p.id),"peer":hex::encode(peer_id(f.sender)),"state":state,"challenge":hex::encode(f.challenge),"delivery_nonce":hex::encode(f.nonce)}));
            }
        }
        Ok(
            serde_json::json!({"state":(["NOT_QUEUED","QUEUED","HOP_CUSTODY","DESTINATION_CUSTODY"][level]),"observations":observations,"ledger_authority":false}),
        )
    }
}

impl Carriage {
    /// Keep a finite recent completion history. Only already processed packets
    /// with independently verified destination receipts, or noncustodial kind-9
    /// control copies, are eligible. Live obligations and ledger/wallet bytes stay.
    pub fn compact_completed(&mut self) -> Result<()> {
        let n: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM packets WHERE processed=1 AND (done=1 OR kind=9)",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        if n <= 256 {
            return Ok(());
        }
        let mut stmt=self.db.prepare("SELECT raw FROM packets WHERE processed=1 AND (done=1 OR kind=9) ORDER BY rowid LIMIT ?1").map_err(err)?;
        let rows = stmt
            .query_map([n - 256], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        let mut ids = Vec::new();
        for raw in rows {
            let p = Packet::decode(&raw.map_err(err)?, self.chain)?;
            if p.kind != 9 {
                let receipt: Vec<u8> = self
                    .db
                    .query_row(
                        "SELECT raw FROM receipts WHERE packet=?1",
                        [p.id.as_slice()],
                        |r| r.get(0),
                    )
                    .map_err(err)?;
                ensure(
                    Frame::decode(&receipt, self.chain)?.discharges(&p),
                    "INVALID_CRYPTO completion collection",
                )?;
            }
            ids.push(p.id);
        }
        drop(stmt);
        let tx = self.db.transaction().map_err(err)?;
        for id in ids {
            for query in [
                "DELETE FROM offline_out WHERE packet=?1",
                "DELETE FROM candidates WHERE source=?1",
                "DELETE FROM hop_receipts WHERE packet=?1",
                "DELETE FROM receipts WHERE packet=?1",
                "DELETE FROM packets WHERE id=?1",
            ] {
                tx.execute(query, [id.as_slice()]).map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        Ok(())
    }
}

impl Carriage {
    /// Coalesce an exact outstanding local offer without changing its signature,
    /// sequence or acknowledgment state. Explicit new packets still use originate.
    pub fn originate_unique(
        &mut self,
        key: &SigningKey,
        destination: Hash,
        kind: u8,
        payload: &[u8],
    ) -> Result<Packet> {
        ensure(
            key.verifying_key().to_bytes() == self.identity,
            "INVALID_CRYPTO origin key",
        )?;
        if let Some(p) = self.queued_copy(destination, kind, payload)? {
            return Ok(p);
        }
        self.originate(key, destination, kind, payload)
    }
    pub(crate) fn queued_copy(
        &self,
        destination: Hash,
        kind: u8,
        payload: &[u8],
    ) -> Result<Option<Packet>> {
        let raw:Option<Vec<u8>>=self.db.query_row("SELECT raw FROM packets WHERE origin=?1 AND kind=?2 AND done=0 AND substr(raw,77,32)=?3 AND substr(raw,130,length(raw)-193)=?4 ORDER BY id LIMIT 1",params![self.identity.as_slice(),kind,destination.as_slice(),payload],|r|r.get(0)).optional().map_err(err)?;
        raw.map(|raw| Packet::decode(&raw, self.chain)).transpose()
    }
    pub(crate) fn pending_block_ids(&self) -> Result<BTreeSet<Hash>> {
        let mut stmt = self
            .db
            .prepare("SELECT raw FROM packets WHERE kind=3 AND processed=0")
            .map_err(err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        let mut ids = BTreeSet::new();
        for raw in rows {
            let p = Packet::decode(&raw.map_err(err)?, self.chain)?;
            ids.insert(crate::kernel::block_id(p.payload())?);
        }
        Ok(ids)
    }
}
