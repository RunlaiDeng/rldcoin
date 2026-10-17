//! Bounded canonical transaction pool; no pool record creates a coin.
use crate::{
    kernel::{decode_tx, Hash, Result},
    store::Store,
};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT {e}")
}
impl Store {
    pub(crate) fn pool_open(&self) -> Result<()> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS pool (id BLOB PRIMARY KEY, raw BLOB NOT NULL); CREATE TABLE IF NOT EXISTS submissions (operation BLOB PRIMARY KEY, raw BLOB NOT NULL);").map_err(err)?;
        let mut stmt = self.db.prepare("SELECT id,raw FROM pool").map_err(err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(err)?;
        let mut n = 0;
        let mut size = 0;
        for row in rows {
            let (id, raw) = row.map_err(err)?;
            let t = decode_tx(&raw, self.ledger().chain_id())?;
            if id != t.id {
                return Err("INVALID pool identity".into());
            }
            n += 1;
            size += raw.len();
        }
        if n > 65536 || size > 64 * 1024 * 1024 {
            return Err("RESOURCE_WAIT pool budget".into());
        }
        Ok(())
    }
    pub fn submit_transaction(&mut self, operation: Hash, raw: &[u8], now: u64) -> Result<Hash> {
        self.clock(now)?;
        if operation == [0; 32] {
            return Err("INVALID operation ID".into());
        }
        let t = decode_tx(raw, self.ledger().chain_id())?;
        let existing: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM submissions WHERE operation=?1",
                [operation.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(x) = existing {
            if x != raw {
                return Err("OPERATION_ID_CONFLICT".into());
            }
            return Ok(t.id);
        }
        let conflict:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 UNION ALL SELECT 1 FROM wallet WHERE id=?1)",[operation.as_slice()],|r|r.get(0)).map_err(err)?;
        if conflict {
            return Err("OPERATION_ID_CONFLICT".into());
        }
        self.pool_insert(raw)?;
        self.db
            .execute(
                "INSERT INTO submissions VALUES(?1,?2)",
                params![operation.as_slice(), raw],
            )
            .map_err(err)?;
        Ok(t.id)
    }
    pub(crate) fn pool_insert(&self, raw: &[u8]) -> Result<()> {
        let t = decode_tx(raw, self.ledger().chain_id())?;
        let old: Option<Vec<u8>> = self
            .db
            .query_row("SELECT raw FROM pool WHERE id=?1", [t.id.as_slice()], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != raw {
                return Err("INVALID pool collision".into());
            }
            return Ok(());
        }
        let (count, size): (i64, i64) = self
            .db
            .query_row(
                "SELECT count(*),coalesce(sum(length(raw)),0) FROM pool",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if count >= 65536 || size < 0 || size as usize + raw.len() > 64 * 1024 * 1024 {
            return Err("RESOURCE_WAIT pool full".into());
        }
        self.db
            .execute(
                "INSERT INTO pool VALUES(?1,?2)",
                params![t.id.as_slice(), raw],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn template_transactions(&self) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self.db.prepare("SELECT raw FROM pool").map_err(err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        let mut ready = Vec::new();
        for row in rows {
            let raw = row.map_err(err)?;
            let t = decode_tx(&raw, self.ledger().chain_id())?;
            if self.ledger().validate_transfer(&raw).is_ok() {
                ready.push((t, raw));
            }
        }
        ready.sort_by(|(a, x), (b, y)| {
            // Products fit u128: CAP * 1638 < 2^128.
            (b.fee * (x.len() as u128))
                .cmp(&(a.fee * (y.len() as u128)))
                .then(a.id.cmp(&b.id))
        });
        let mut inputs = BTreeSet::new();
        let mut result = Vec::new();
        let mut size = 270;
        for (t, raw) in ready {
            if result.len() == 128 {
                break;
            }
            if size + 4 + raw.len() > 262144 || t.inputs.iter().any(|i| inputs.contains(i)) {
                continue;
            }
            size += 4 + raw.len();
            inputs.extend(t.inputs);
            result.push(raw)
        }
        Ok(result)
    }
}
