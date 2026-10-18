//! Explicitly admitted one-way file adapter; no zero-challenge TLS fallback.
use crate::{
    carriage::Carriage,
    contact::{peer_id, Frame, Packet},
    kernel::{Hash, Result},
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, OptionalExtension};
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT offline {e}")
}
fn ensure(ok: bool, s: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(s.into())
    }
}
impl Carriage {
    pub(crate) fn offline_open(&self) -> Result<()> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS offline_out (peer BLOB NOT NULL,packet BLOB NOT NULL,raw BLOB NOT NULL,PRIMARY KEY(peer,packet));CREATE TABLE IF NOT EXISTS candidates (key BLOB PRIMARY KEY,source BLOB NOT NULL);").map_err(err)?;
        let mut stmt = self
            .db
            .prepare("SELECT peer,packet,raw FROM offline_out")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(r) = rows.next().map_err(err)? {
            let peer: Vec<u8> = r.get(0).map_err(err)?;
            let id: Vec<u8> = r.get(1).map_err(err)?;
            let raw: Vec<u8> = r.get(2).map_err(err)?;
            let f = Frame::decode(&raw, self.chain)?;
            let p = f.authenticate_delivery(
                self.identity,
                peer_id(
                    peer.try_into()
                        .map_err(|_| "INVALID_ENCODING offline peer")?,
                ),
                [0; 32],
                true,
            )?;
            ensure(
                id == p.id && self.packet(p.id)?.is_some_and(|old| old.raw() == p.raw()),
                "INVALID_CRYPTO retained offline delivery",
            )?;
        }
        Ok(())
    }
    pub fn prepare_offline(&self, key: &SigningKey, peer: Hash, p: &Packet) -> Result<Frame> {
        ensure(
            key.verifying_key().to_bytes() == self.identity,
            "INVALID_CRYPTO offline identity",
        )?;
        ensure(
            self.packet(p.id())?.is_some_and(|x| x.raw() == p.raw()),
            "MISSING_HISTORY durable outgoing packet",
        )?;
        let old: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM offline_out WHERE peer=?1 AND packet=?2",
                params![peer.as_slice(), p.id().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(raw) = old {
            let frame = Frame::decode(&raw, self.chain)?;
            let retained =
                frame.authenticate_delivery(self.identity, peer_id(peer), [0; 32], true)?;
            ensure(
                retained.id() == p.id() && retained.raw() == p.raw(),
                "INVALID_CRYPTO retained offline delivery",
            )?;
            return Ok(frame);
        }
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(err)?;
        ensure(nonce != [0; 32], "RESOURCE_WAIT offline entropy")?;
        let frame = Frame::delivery(self.chain, key, peer_id(peer), [0; 32], nonce, p)?;
        if p.kind() != 9 {
            self.capacity(frame.raw().len() + 96, 0)?;
            self.db
                .execute(
                    "INSERT INTO offline_out VALUES(?1,?2,?3)",
                    params![peer.as_slice(), p.id().as_slice(), frame.raw()],
                )
                .map_err(err)?;
        }
        Ok(frame)
    }
    pub fn offline_receipt(&mut self, raw: &[u8], peer: Hash) -> Result<()> {
        let f = Frame::decode(raw, self.chain)?;
        ensure(
            f.kind == 3 && f.sender == peer && f.challenge == [0; 32],
            "INVALID_CRYPTO offline receipt role",
        )?;
        let id = f.packet_id.ok_or("INVALID_ENCODING receipt packet")?;
        let original: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM offline_out WHERE peer=?1 AND packet=?2",
                params![peer.as_slice(), id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        let delivery = Frame::decode(
            &original.ok_or("MISSING_HISTORY exact offline delivery")?,
            self.chain,
        )?;
        let retained =
            delivery.authenticate_delivery(self.identity, peer_id(peer), [0; 32], true)?;
        let packet = self.packet(id)?.ok_or("MISSING_HISTORY original packet")?;
        ensure(
            retained.id() == id && retained.raw() == packet.raw(),
            "INVALID_CRYPTO retained offline delivery",
        )?;
        let result = f.authenticate_receipt(&delivery, peer)?;
        if result == 1 {
            self.retain_destination_receipt(&packet, &f)?;
        }
        if matches!(result, 0 | 1) {
            self.retain_hop_receipt(id, &f)?;
        }
        Ok(())
    }
    pub(crate) fn discover(&self, p: &Packet) -> Result<bool> {
        ensure(p.kind() == 8, "INVALID_ENCODING discovery packet")?;
        let mut changed = false;
        for key in p.payload()[2..].as_chunks::<32>().0 {
            let count: i64 = self
                .db
                .query_row("SELECT count(*) FROM candidates", [], |r| r.get(0))
                .map_err(err)?;
            if count >= 1024 {
                break;
            }
            self.capacity(64, 0)?;
            changed |= self
                .db
                .execute(
                    "INSERT OR IGNORE INTO candidates VALUES(?1,?2)",
                    params![key.as_slice(), p.id().as_slice()],
                )
                .map_err(err)?
                > 0;
        }
        Ok(changed)
    }
    pub fn candidate_identities(&self) -> Result<Vec<Hash>> {
        let mut stmt = self
            .db
            .prepare("SELECT key,source FROM candidates ORDER BY key")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(err)? {
            let key: Hash = r
                .get::<_, Vec<u8>>(0)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING candidate key")?;
            let source: Hash = r
                .get::<_, Vec<u8>>(1)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING candidate source")?;
            let p = self
                .packet(source)?
                .ok_or("MISSING_HISTORY discovery source")?;
            ensure(
                p.kind() == 8 && p.payload()[2..].as_chunks::<32>().0.contains(&key),
                "INVALID_CRYPTO discovery observation",
            )?;
            out.push(key);
        }
        Ok(out)
    }
}
