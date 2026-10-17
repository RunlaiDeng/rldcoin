//! Durable exact user intent. A reservation is local policy, never a chain lock.
use crate::{
    kernel::{decode_tx, decode_unsigned, hash, tag, Hash, Result},
    store::Store,
};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT {e}")
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn h(x: Vec<u8>) -> Result<Hash> {
    x.try_into().map_err(|_| "INVALID wallet hash".into())
}
fn rev(x: Vec<u8>) -> Result<u128> {
    Ok(u128::from_be_bytes(
        x.try_into().map_err(|_| "INVALID wallet revision")?,
    ))
}
#[derive(Debug, PartialEq, Eq)]
pub struct Balance {
    pub unspent: u128,
    pub immature: u128,
    pub mature: u128,
    pub reserved: u128,
    pub available: u128,
}
impl Store {
    pub(crate) fn wallet_open(&self) -> Result<()> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS wallet (id BLOB PRIMARY KEY, unsigned BLOB NOT NULL, reviewed_tip BLOB NOT NULL, reviewed_revision BLOB NOT NULL, digest BLOB NOT NULL, signed BLOB, signing_tip BLOB, waived INTEGER NOT NULL CHECK(waived IN (0,1))); ").map_err(err)?;
        let mut stmt=self.db.prepare("SELECT id,unsigned,reviewed_tip,reviewed_revision,digest,signed,signing_tip FROM wallet").map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(r) = rows.next().map_err(err)? {
            let id = h(r.get(0).map_err(err)?)?;
            ensure(id != [0; 32], "INVALID wallet operation ID")?;
            let u: Vec<u8> = r.get(1).map_err(err)?;
            let tip = h(r.get(2).map_err(err)?)?;
            let revision = rev(r.get(3).map_err(err)?)?;
            let digest = h(r.get(4).map_err(err)?)?;
            ensure(
                digest == self.review_digest(id, tip, revision, &u),
                "INVALID retained review",
            )?;
            self.replay(tip)?.validate_unsigned(&u)?;
            let signed: Option<Vec<u8>> = r.get(5).map_err(err)?;
            let signing: Option<Vec<u8>> = r.get(6).map_err(err)?;
            match (signed, signing) {
                (Some(x), Some(t)) => {
                    ensure(
                        x.len() == u.len() + 64 && x[..u.len()] == u,
                        "INVALID retained signature intent",
                    )?;
                    self.replay(h(t)?)?.validate_transfer(&x)?;
                }
                (None, None) => {}
                _ => return Err("INVALID partial wallet publication".into()),
            }
        }
        Ok(())
    }
    fn review_digest(&self, id: Hash, tip: Hash, revision: u128, u: &[u8]) -> Hash {
        hash(
            "REVIEW",
            &[
                self.ledger().chain_id().as_slice(),
                id.as_slice(),
                tip.as_slice(),
                revision.to_be_bytes().as_slice(),
                u,
            ]
            .concat(),
        )
    }
    pub fn review_transfer(&mut self, id: Hash, u: &[u8], now: u64) -> Result<Hash> {
        self.clock(now)?;
        ensure(id != [0; 32], "INVALID operation ID")?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT unsigned,digest FROM wallet WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((old, digest)) = existing {
            ensure(old == u, "OPERATION_ID_CONFLICT")?;
            return h(digest);
        }
        let exists: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 UNION ALL SELECT 1 FROM submissions WHERE operation=?1)",
                [id.as_slice()],
                |r| r.get(0),
            )
            .map_err(err)?;
        ensure(!exists, "OPERATION_ID_CONFLICT")?;
        self.ledger().validate_unsigned(u)?;
        let tx = decode_unsigned(u, self.ledger().chain_id())?;
        let reserved = self.reservations()?;
        ensure(
            tx.inputs.iter().all(|i| !reserved.contains(i)),
            "CONFLICT reserved input",
        )?;
        let tip = self.ledger().tip().id();
        let revision = self.revision();
        let digest = self.review_digest(id, tip, revision, u);
        self.db
            .execute(
                "INSERT INTO wallet VALUES(?1,?2,?3,?4,?5,NULL,NULL,0)",
                params![
                    id.as_slice(),
                    u,
                    tip.as_slice(),
                    revision.to_be_bytes().as_slice(),
                    digest.as_slice()
                ],
            )
            .map_err(err)?;
        Ok(digest)
    }
    /// An explicit signing request only. Read-only recovery uses signed_operation.
    pub fn sign_review(
        &mut self,
        id: Hash,
        digest: Hash,
        key: &SigningKey,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.clock(now)?;
        type ReviewRow = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, bool);
        let (u, d, existing, waived): ReviewRow = self
            .db
            .query_row(
                "SELECT unsigned,digest,signed,waived FROM wallet WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(err)?
            .ok_or("INVALID unknown review")?;
        ensure(h(d)? == digest, "INVALID review digest")?;
        let tx = decode_unsigned(&u, self.ledger().chain_id())?;
        ensure(
            tx.owner == key.verifying_key().to_bytes(),
            "INVALID signing owner",
        )?;
        if let Some(x) = existing {
            return Ok(x);
        }
        ensure(!waived, "CONFLICT waived review")?;
        self.ledger().validate_unsigned(&u)?;
        let signature = key.sign(&[tag("TRANSFER"), u.clone()].concat());
        let mut x = u;
        x.extend(signature.to_bytes());
        decode_tx(&x, self.ledger().chain_id())?;
        // SQLite's autocommit is synchronized before any signature is returned.
        self.db
            .execute(
                "UPDATE wallet SET signed=?1,signing_tip=?2 WHERE id=?3 AND signed IS NULL",
                params![x, self.ledger().tip().id().as_slice(), id.as_slice()],
            )
            .map_err(err)?;
        Ok(x)
    }
    pub fn signed_operation(&self, id: Hash) -> Result<Option<Vec<u8>>> {
        self.db
            .query_row(
                "SELECT signed FROM wallet WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)
            .map(|x: Option<Option<Vec<u8>>>| x.flatten())
    }
    /// Explicit local withdrawal of the reservation. Does not revoke a signature.
    pub fn waive_reservation(
        &mut self,
        id: Hash,
        acknowledge_conflicting_branch: bool,
    ) -> Result<()> {
        ensure(
            acknowledge_conflicting_branch,
            "INVALID withdrawal acknowledgment required",
        )?;
        ensure(
            self.db
                .execute("UPDATE wallet SET waived=1 WHERE id=?1", [id.as_slice()])
                .map_err(err)?
                == 1,
            "INVALID unknown operation",
        )
    }
    fn reservations(&self) -> Result<BTreeSet<Vec<u8>>> {
        let mut result = BTreeSet::new();
        let mut stmt = self
            .db
            .prepare("SELECT unsigned FROM wallet WHERE waived=0")
            .map_err(err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        for raw in rows {
            result.extend(decode_unsigned(&raw.map_err(err)?, self.ledger().chain_id())?.inputs)
        }
        Ok(result)
    }
    pub fn wallet_state(&self, owner: Hash) -> Result<Balance> {
        let reserved = self.reservations()?;
        let mut b = Balance {
            unspent: 0,
            immature: 0,
            mature: 0,
            reserved: 0,
            available: 0,
        };
        let next = self.ledger().tip().height() + 1;
        for (id, c) in self.ledger().coins() {
            if c.owner != owner {
                continue;
            }
            b.unspent += c.amount;
            if c.maturity > next {
                b.immature += c.amount
            } else {
                b.mature += c.amount;
                if reserved.contains(id) {
                    b.reserved += c.amount
                }
            }
        }
        b.available = b.mature - b.reserved;
        Ok(b)
    }
    pub fn wallet_outputs(&self, owner: Hash) -> Result<Vec<(Vec<u8>, crate::kernel::Coin, bool)>> {
        let reserved = self.reservations()?;
        Ok(self
            .ledger()
            .coins()
            .iter()
            .filter(|(_, c)| c.owner == owner)
            .map(|(id, c)| (id.clone(), c.clone(), reserved.contains(id)))
            .collect())
    }
}
