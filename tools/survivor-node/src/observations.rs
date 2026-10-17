//! Revision-bound observations derived from exact native-replayed histories.
//! This module cannot create ledger authority or prevent a valid reorganization.
use crate::{
    kernel::{block_id, decode_tx, Hash, Ledger, Result},
    store::Store,
};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::BTreeSet;
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT observations {e}")
}
/// Extract canonical transactions only from a block already validated by the kernel.
pub(crate) fn transactions(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
    if raw.len() < 270 {
        return Err("INVALID_ENCODING block body".into());
    }
    let n = u16::from_be_bytes(raw[268..270].try_into().unwrap());
    let mut at = 270usize;
    let mut result = Vec::new();
    for _ in 0..n {
        let len = raw
            .get(at..at + 4)
            .ok_or("INVALID_ENCODING transaction length")?;
        let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
        at += 4;
        let end = at
            .checked_add(len)
            .ok_or("INVALID_ENCODING length overflow")?;
        result.push(
            raw.get(at..end)
                .ok_or("INVALID_ENCODING transaction bytes")?
                .to_vec(),
        );
        at = end;
    }
    if at != raw.len() {
        return Err("INVALID_ENCODING trailing block bytes".into());
    }
    Ok(result)
}
impl Store {
    pub(crate) fn observations_open(&self) -> Result<()> {
        self.db.execute_batch("CREATE TABLE IF NOT EXISTS changes (revision BLOB PRIMARY KEY,body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS reoffer (block BLOB NOT NULL,ordinal INTEGER NOT NULL,height BLOB NOT NULL,PRIMARY KEY(block,ordinal));").map_err(err)?;
        // Notification history is checked against native replay, never authority.
        Ok(())
    }
    pub(crate) fn branch_change(&self, next: &Ledger, raw: &[u8]) -> Result<(Value, Vec<Vec<u8>>)> {
        self.branch_change_from(self.ledger(), self.revision(), next, raw)
    }
    pub(crate) fn branch_change_from(
        &self,
        before: &Ledger,
        revision: u128,
        next: &Ledger,
        raw: &[u8],
    ) -> Result<(Value, Vec<Vec<u8>>)> {
        let (attached, detached) =
            if raw[36..68] == before.tip().id() && block_id(raw)? == next.tip().id() {
                (vec![raw.to_vec()], Vec::new())
            } else {
                let old = self.ancestry_ids(before.tip().id())?;
                let oldset: BTreeSet<_> = old.iter().copied().collect();
                let mut attached = Vec::new();
                let mut id = next.tip().id();
                let incoming = block_id(raw)?;
                while !oldset.contains(&id) {
                    let b = if id == incoming {
                        raw.to_vec()
                    } else {
                        self.get_block(id)?
                    };
                    id = b[36..68].try_into().unwrap();
                    attached.push(b);
                }
                attached.reverse();
                let cut = old
                    .iter()
                    .position(|x| *x == id)
                    .ok_or("MISSING_HISTORY common ancestor")?;
                let detached = old[cut + 1..]
                    .iter()
                    .map(|x| self.get_block(*x))
                    .collect::<Result<Vec<_>>>()?;
                (attached, detached)
            };
        let entries = |blocks: &[Vec<u8>]| -> Result<Vec<Value>> {
            blocks.iter().map(|b| Ok(json!({"block_id":hex::encode(block_id(b)?),"height":u128::from_be_bytes(b[68..84].try_into().unwrap()).to_string(),"transactions":transactions(b)?.iter().map(|x|decode_tx(x,self.ledger().chain_id()).map(|t|hex::encode(t.id))).collect::<Result<Vec<_>>>()?}))).collect()
        };
        let keys: BTreeSet<_> = before.coins().keys().chain(next.coins().keys()).collect();
        let mut changed = Vec::new();
        for k in keys {
            let old_coin = before.coins().get(k);
            let after = next.coins().get(k);
            let eligible =
                |c: Option<&crate::kernel::Coin>, h: u128| c.map(|c| c.maturity <= h + 1);
            if old_coin != after
                || eligible(old_coin, before.tip().height()) != eligible(after, next.tip().height())
            {
                changed.push(hex::encode(k));
            }
        }
        Ok((
            json!({"previous_tip":hex::encode(before.tip().id()),"selected_tip":hex::encode(next.tip().id()),"previous_revision":revision.to_string(),"revision":(revision+1).to_string(),"state_root":hex::encode(next.tip().root()),"detached":entries(&detached)?,"attached":entries(&attached)?,"changed_outputs":changed,"confidence":"CONDITIONAL"}),
            detached,
        ))
    }
    pub fn changes_since(&self, revision: u128) -> Result<Value> {
        if revision > self.revision() || self.revision() - revision > 128 {
            return Err("RESYNC_REQUIRED".into());
        }
        let mut changes = Vec::new();
        let mut size = 0;
        for r in revision + u128::from(revision < self.revision())..=self.revision() {
            if revision == self.revision() {
                break;
            }
            let body: Option<String> = self
                .db
                .query_row(
                    "SELECT body FROM changes WHERE revision=?1",
                    [r.to_be_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(err)?;
            let body = body.ok_or("RESYNC_REQUIRED")?;
            size += body.len();
            if size > 1024 * 1024 {
                return Err("RESYNC_REQUIRED".into());
            }
            let v: Value = serde_json::from_str(&body).map_err(err)?;
            // Anchor observations to the committed native transition, not a peer hint.
            let tip:Vec<u8>=self.db.query_row("SELECT new_tip FROM operations WHERE revision=?1 AND selected=1 AND committed=1",[r.to_be_bytes().as_slice()],|row|row.get(0)).map_err(err)?;
            if v["revision"] != r.to_string() || v["selected_tip"] != hex::encode(tip) {
                return Err("INVALID_ENCODING change binding".into());
            }
            changes.push(v);
        }
        Ok(json!({"changes":changes}))
    }
    pub fn get_transaction(&self, id: Hash) -> Result<Vec<u8>> {
        let x: Option<Vec<u8>> = self
            .db
            .query_row("SELECT raw FROM pool WHERE id=?1", [id.as_slice()], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?;
        if let Some(x) = x {
            if decode_tx(&x, self.ledger().chain_id())?.id == id {
                return Ok(x);
            }
            return Err("INVALID_ENCODING transaction index".into());
        }
        let mut stmt = self
            .db
            .prepare("SELECT raw FROM blocks ORDER BY id")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            for x in transactions(&row.get::<_, Vec<u8>>(0).map_err(err)?)? {
                if decode_tx(&x, self.ledger().chain_id())?.id == id {
                    return Ok(x);
                }
            }
        }
        Err("MISSING_HISTORY transaction".into())
    }
    pub fn transfer_observation(&self, raw: &[u8]) -> Result<Value> {
        let t = decode_tx(raw, self.ledger().chain_id())?;
        let selected = self.selected_ids()?;
        let mut inclusion = None;
        let mut spent = BTreeSet::new();
        for id in selected.iter().skip(1) {
            let b = self.get_block(*id)?;
            for x in transactions(&b)? {
                let tx = decode_tx(&x, self.ledger().chain_id())?;
                if tx.id == t.id {
                    inclusion = Some((*id, u128::from_be_bytes(b[68..84].try_into().unwrap())));
                }
                spent.extend(tx.inputs);
            }
        }
        let mut detached = false;
        if inclusion.is_none() {
            let mut seen = BTreeSet::new();
            let mut stmt = self
                .db
                .prepare("SELECT new_tip FROM operations WHERE committed=1 AND selected=1")
                .map_err(err)?;
            let mut rows = stmt.query([]).map_err(err)?;
            while let Some(row) = rows.next().map_err(err)? {
                let mut id: Hash = row
                    .get::<_, Vec<u8>>(0)
                    .map_err(err)?
                    .try_into()
                    .map_err(|_| "INVALID_ENCODING historical head")?;
                while id != self.ledger().chain_id() && seen.insert(id) {
                    let b = self.get_block(id)?;
                    for x in transactions(&b)? {
                        if decode_tx(&x, self.ledger().chain_id())?.id == t.id {
                            detached = true;
                        }
                    }
                    id = b[36..68].try_into().unwrap();
                }
            }
        }
        let reason = if self.ledger().tip().height() + 1 > t.expiry {
            Some("EXPIRED")
        } else if t.inputs.iter().any(|i| spent.contains(i)) && inclusion.is_none() {
            Some("CONFLICTED")
        } else if self.ledger().validate_transfer(raw).is_ok() {
            Some("READY")
        } else if t
            .inputs
            .iter()
            .any(|i| !self.ledger().coins().contains_key(i))
        {
            Some("WAITING_FOR_HISTORY")
        } else if t.inputs.iter().any(|i| {
            self.ledger()
                .coins()
                .get(i)
                .is_some_and(|c| c.maturity > self.ledger().tip().height() + 1)
        }) {
            Some("IMMATURE")
        } else {
            Some("INVALID")
        };
        let state = if inclusion.is_some() {
            "INCLUDED"
        } else if detached {
            "DETACHED"
        } else {
            match reason {
                Some("IMMATURE") => "UNSEEN",
                Some(s) => s,
                None => "UNSEEN",
            }
        };
        let outputs:Vec<_>=t.outputs.iter().enumerate().map(|(i,_)|{
            let mut key=t.id.to_vec();key.extend((i as u16).to_be_bytes());
            let coin=self.ledger().coins().get(&key);
            json!({"outpoint":hex::encode(&key),"state":if coin.is_some(){"UNSPENT"}else if inclusion.is_some(){"SPENT"}else{"ABSENT"},"maturity_height":coin.map(|c|c.maturity.to_string()),"eligible_next_height":coin.map(|c|c.maturity<=self.ledger().tip().height()+1)})
        }).collect();
        Ok(
            json!({"transaction_id":hex::encode(t.id),"ledger":state,"readiness":reason,"inclusion":inclusion.map(|(id,h)|json!({"block_id":hex::encode(id),"height":h.to_string(),"confirmations":(self.ledger().tip().height()-h+1).to_string()})),"outputs":outputs,"confidence":"CONDITIONAL"}),
        )
    }
    /// A bounded recovery pass. References survive pool pressure; no signature is
    /// replaced, and the original detached blocks stay in the complete archive.
    pub fn reoffer_pending(&self) -> Result<()> {
        let mut stmt = self
            .db
            .prepare("SELECT block,ordinal FROM reoffer ORDER BY height,block,ordinal LIMIT 128")
            .map_err(err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u16>(1)?)))
            .map_err(err)?;
        let records = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(err)?;
        drop(stmt);
        for (id, n) in records {
            let id: Hash = id
                .try_into()
                .map_err(|_| "INVALID_ENCODING reoffer block")?;
            let block = self.get_block(id)?;
            let all = transactions(&block)?;
            let raw = all
                .get(n as usize)
                .ok_or("INVALID_ENCODING reoffer ordinal")?;
            self.pool_insert(raw)?;
            self.db
                .execute(
                    "DELETE FROM reoffer WHERE block=?1 AND ordinal=?2",
                    params![id.as_slice(), n],
                )
                .map_err(err)?;
        }
        Ok(())
    }
}

impl Store {
    pub fn payment_operation(&self, id: Hash) -> Result<Option<Value>> {
        type Row = (Vec<u8>, Option<Vec<u8>>, bool, Vec<u8>);
        let row: Option<Row> = self
            .db
            .query_row(
                "SELECT unsigned,signed,waived,digest FROM wallet WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((u, x, waived, digest)) = row {
            let mut v = if let Some(x) = &x {
                self.transfer_observation(x)?
            } else {
                json!({"transaction_id":hex::encode(crate::kernel::decode_unsigned(&u,self.ledger().chain_id())?.id),"ledger":"UNSEEN","inclusion":null})
            };
            v["local_intent"] = json!(if waived {
                "WITHDRAWN"
            } else if x.is_some() {
                "SIGNED"
            } else {
                "REVIEWED"
            });
            v["transaction_hex"] = json!(x.map(hex::encode));
            v["review_digest"] = json!(hex::encode(digest));
            return Ok(Some(v));
        }
        let x: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM submissions WHERE operation=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        x.map(|x| {
            let mut v = self.transfer_observation(&x)?;
            v["transaction_hex"] = json!(hex::encode(x));
            Ok(v)
        })
        .transpose()
    }
}
