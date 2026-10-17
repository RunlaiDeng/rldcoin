//! Durable exact user intent. A reservation is local policy, never a chain lock.
use crate::{
    kernel::{decode_tx, decode_unsigned, hash, tag, Hash, Ledger, Result},
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
pub(crate) struct Review {
    pub unsigned: Vec<u8>,
    pub reviewed_tip: Hash,
    pub reviewed_revision: u128,
    pub digest: Hash,
    pub signed: Option<Vec<u8>>,
    pub signing_tip: Option<Hash>,
    pub waived: bool,
}
/// Counts are completeness checks only, never ledger authority. Context indexes
/// locate one row at a time within the existing database budget. Only the cold
/// store's fully executed selected heads may satisfy these requests.
pub(crate) struct ColdWallet {
    reviews: u64,
    signatures: u64,
}
impl ColdWallet {
    pub(crate) fn selected_head(
        &mut self,
        store: &Store,
        ledger: &Ledger,
        revision: u128,
    ) -> Result<()> {
        if self.reviews == 0 && self.signatures == 0 {
            return Ok(());
        }
        let tip = ledger.tip().id();
        let mut stmt = store
            .db
            .prepare("SELECT id FROM wallet WHERE reviewed_revision=?1 OR signing_tip=?2")
            .map_err(err)?;
        let mut rows = stmt
            .query(params![revision.to_be_bytes().as_slice(), tip.as_slice()])
            .map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            let id = h(row.get(0).map_err(err)?)?;
            let review = store
                .review_record(id)?
                .ok_or("INVALID missing wallet context")?;
            if review.reviewed_revision == revision {
                ensure(
                    review.reviewed_tip == tip,
                    "INVALID wallet review selected context",
                )?;
                ledger.validate_unsigned(&review.unsigned)?;
                self.reviews = self
                    .reviews
                    .checked_sub(1)
                    .ok_or("INVALID duplicate wallet context")?;
            }
            if review.signing_tip == Some(tip) {
                ensure(
                    review.reviewed_revision <= revision,
                    "INVALID wallet signing precedes review",
                )?;
                ledger.validate_transfer(
                    review
                        .signed
                        .as_ref()
                        .ok_or("INVALID partial wallet publication")?,
                )?;
                self.signatures = self
                    .signatures
                    .checked_sub(1)
                    .ok_or("INVALID duplicate signing context")?;
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<()> {
        ensure(
            self.reviews == 0 && self.signatures == 0,
            "INVALID unresolved wallet selected context",
        )
    }
}
impl Store {
    fn wallet_write(&self, result: rusqlite::Result<usize>) -> Result<()> {
        match result {
            Ok(1) => Ok(()),
            Ok(_) => Err(self.storage_fault("wallet journal write not confirmed")),
            Err(e) => Err(self.storage_wait(format!("wallet journal commit: {e}"))),
        }
    }
    pub(crate) fn wallet_prepare_cold(&self) -> Result<ColdWallet> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS wallet (id BLOB PRIMARY KEY, unsigned BLOB NOT NULL, reviewed_tip BLOB NOT NULL, reviewed_revision BLOB NOT NULL, digest BLOB NOT NULL, signed BLOB, signing_tip BLOB, waived INTEGER NOT NULL CHECK(waived IN (0,1))); CREATE INDEX IF NOT EXISTS wallet_review_context ON wallet(reviewed_revision); CREATE INDEX IF NOT EXISTS wallet_signing_context ON wallet(signing_tip);").map_err(err)?;
        let (reviews, signatures): (i64, i64) = self
            .db
            .query_row("SELECT count(*),count(signed) FROM wallet", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .map_err(err)?;
        Ok(ColdWallet {
            reviews: reviews.try_into().map_err(|_| "INVALID wallet count")?,
            signatures: signatures
                .try_into()
                .map_err(|_| "INVALID signature count")?,
        })
    }
    /// Every use of a retained intent checks its complete review binding and any
    /// exact signature. This never signs, selects a state or trusts decoded state.
    pub(crate) fn review_record(&self, id: Hash) -> Result<Option<Review>> {
        type Row = (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            bool,
        );
        let row:Option<Row>=self.db.query_row("SELECT unsigned,reviewed_tip,reviewed_revision,digest,signed,signing_tip,waived FROM wallet WHERE id=?1",[id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(err)?;
        row.map(
            |(unsigned, tip, revision, digest, signed, signing_tip, waived)| {
                let checked = (|| -> Result<Review> {
                    let reviewed_tip = h(tip)?;
                    let revision = rev(revision)?;
                    let digest = h(digest)?;
                    ensure(
                        id != [0; 32]
                            && digest == self.review_digest(id, reviewed_tip, revision, &unsigned),
                        "retained review binding",
                    )?;
                    decode_unsigned(&unsigned, self.ledger().chain_id())?;
                    let signing_tip = signing_tip.map(h).transpose()?;
                    match (&signed, signing_tip) {
                        (Some(x), Some(_)) => {
                            ensure(
                                x.len() == unsigned.len() + 64 && x[..unsigned.len()] == unsigned,
                                "retained signature intent",
                            )?;
                            decode_tx(x, self.ledger().chain_id())?;
                        }
                        (None, None) => {}
                        _ => return Err("partial retained signature".into()),
                    }
                    Ok(Review {
                        unsigned,
                        reviewed_tip,
                        reviewed_revision: revision,
                        digest,
                        signed,
                        signing_tip,
                        waived,
                    })
                })();
                checked.map_err(|_| self.storage_fault("retained wallet review/signature binding"))
            },
        )
        .transpose()
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
        if let Some(review) = self.review_record(id)? {
            ensure(review.unsigned == u, "OPERATION_ID_CONFLICT")?;
            return Ok(review.digest);
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
        self.wallet_write(self.db.execute(
            "INSERT INTO wallet VALUES(?1,?2,?3,?4,?5,NULL,NULL,0)",
            params![
                id.as_slice(),
                u,
                tip.as_slice(),
                revision.to_be_bytes().as_slice(),
                digest.as_slice()
            ],
        ))?;
        let retained = self
            .review_record(id)?
            .ok_or_else(|| self.storage_fault("missing committed review"))?;
        if retained.digest != digest
            || retained.unsigned != u
            || retained.signed.is_some()
            || retained.waived
        {
            return Err(self.storage_fault("committed review differs from request"));
        }
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
        let review = self.review_record(id)?.ok_or("INVALID unknown review")?;
        ensure(review.digest == digest, "INVALID_CRYPTO review digest")?;
        let u = review.unsigned;
        let tx = decode_unsigned(&u, self.ledger().chain_id())?;
        ensure(
            tx.owner == key.verifying_key().to_bytes(),
            "INVALID_CRYPTO signing owner",
        )?;
        if let Some(x) = review.signed {
            return Ok(x);
        }
        ensure(self.freshness()? != "FRESHNESS_UNKNOWN", "FRESHNESS_UNKNOWN signing requires intent reconciliation and explicit risk acknowledgment")?;
        ensure(!review.waived, "CONFLICT waived review")?;
        self.ledger().validate_unsigned(&u)?;
        let signature = key.sign(&[tag("TRANSFER"), u.clone()].concat());
        let mut x = u;
        x.extend(signature.to_bytes());
        decode_tx(&x, self.ledger().chain_id())?;
        // SQLite's autocommit is synchronized before any signature is returned.
        self.wallet_write(self.db.execute(
            "UPDATE wallet SET signed=?1,signing_tip=?2 WHERE id=?3 AND signed IS NULL",
            params![x, self.ledger().tip().id().as_slice(), id.as_slice()],
        ))?;
        let retained = self
            .review_record(id)?
            .ok_or_else(|| self.storage_fault("missing committed signature"))?;
        if retained.digest != digest || retained.signed.as_ref() != Some(&x) {
            return Err(self.storage_fault("committed signature differs from request"));
        }
        Ok(x)
    }
    pub fn signed_operation(&self, id: Hash) -> Result<Option<Vec<u8>>> {
        Ok(self.review_record(id)?.and_then(|r| r.signed))
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
        ensure(self.storage_ready(), "RESOURCE_WAIT restart required")?;
        let prior = self.review_record(id)?.ok_or("INVALID unknown operation")?;
        self.wallet_write(
            self.db
                .execute("UPDATE wallet SET waived=1 WHERE id=?1", [id.as_slice()]),
        )?;
        let retained = self
            .review_record(id)?
            .ok_or_else(|| self.storage_fault("missing committed waiver"))?;
        if !retained.waived || retained.digest != prior.digest || retained.signed != prior.signed {
            return Err(self.storage_fault("committed waiver differs from request"));
        }
        Ok(())
    }
    pub(crate) fn reservations(&self) -> Result<BTreeSet<Vec<u8>>> {
        let mut result = BTreeSet::new();
        let mut stmt = self
            .db
            .prepare("SELECT id FROM wallet WHERE waived=0")
            .map_err(err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(err)?;
        for id in rows {
            let review = self
                .review_record(h(id.map_err(err)?)?)?
                .ok_or("INVALID missing wallet reservation")?;
            result.extend(decode_unsigned(&review.unsigned, self.ledger().chain_id())?.inputs)
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
