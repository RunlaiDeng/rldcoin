//! Revision-bound observations derived from exact native-replayed histories.
//! This module cannot create ledger authority or prevent a valid reorganization.
use crate::{
    kernel::{block_id, decode_tx, Hash, Ledger, Result, Tx},
    observation_cache::{Anchor, Block, Delta, Witness, DELTA_BYTES},
    store::Store,
};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
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
    /// Only generated, native-executed transition parts may reach this helper.
    /// Parse all fallible data before committing value; oversized changes simply
    /// invalidate the optional process-local observation set after that commit.
    pub(crate) fn observation_delta(
        &self,
        before: Anchor,
        after: Anchor,
        event: &Value,
        history: &[Vec<u8>],
        incoming: &[u8],
    ) -> Result<Option<Delta>> {
        let attached = event["attached"]
            .as_array()
            .ok_or("INVALID observation attached")?;
        let detached = event["detached"]
            .as_array()
            .ok_or("INVALID observation detached")?;
        if attached.len() + detached.len() > 64 {
            return Ok(None);
        }
        let mut bytes = 0usize;
        let mut read = |entries: &[Value]| -> Result<Option<Vec<Block>>> {
            let mut blocks = Vec::new();
            for entry in entries {
                let id: Hash = hex::decode(
                    entry["block_id"]
                        .as_str()
                        .ok_or("INVALID observation block")?,
                )
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID observation ID")?;
                let raw = if block_id(incoming)? == id {
                    incoming.to_vec()
                } else if let Some(raw) = history.iter().find(|b| block_id(b).ok() == Some(id)) {
                    raw.clone()
                } else {
                    self.get_block(id)?
                };
                bytes = bytes
                    .checked_add(raw.len())
                    .ok_or("RESOURCE_WAIT observation size")?;
                if bytes > DELTA_BYTES {
                    return Ok(None);
                }
                let transactions = transactions(&raw)?
                    .into_iter()
                    .map(|raw| {
                        let tx = decode_tx(&raw, self.ledger().chain_id())?;
                        Ok((raw, tx))
                    })
                    .collect::<Result<Vec<_>>>()?;
                blocks.push(Block {
                    id,
                    height: u128::from_be_bytes(raw[68..84].try_into().unwrap()),
                    transactions,
                });
            }
            Ok(Some(blocks))
        };
        let Some(detached) = read(detached)? else {
            return Ok(None);
        };
        let Some(attached) = read(attached)? else {
            return Ok(None);
        };
        Ok(Some(Delta {
            before,
            after,
            detached,
            attached,
        }))
    }
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
                let old = if before.tip().id() == self.ledger().tip().id() {
                    self.selected_ids()?
                } else {
                    self.ancestry_ids(before.tip().id())?
                };
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
        self.branch_change_parts(before, revision, next, &attached, &detached)
    }
    pub(crate) fn branch_change_parts(
        &self,
        before: &Ledger,
        revision: u128,
        next: &Ledger,
        attached: &[Vec<u8>],
        detached: &[Vec<u8>],
    ) -> Result<(Value, Vec<Vec<u8>>)> {
        let entries = |blocks: &[Vec<u8>]| -> Result<Vec<Value>> {
            let mut result = Vec::new();
            for b in blocks {
                let height = u128::from_be_bytes(b[68..84].try_into().unwrap());
                let txs = transactions(b)?
                    .iter()
                    .map(|x| decode_tx(x, self.ledger().chain_id()))
                    .collect::<Result<Vec<_>>>()?;
                let amount = txs
                    .iter()
                    .try_fold(crate::kernel::issuance(height).0, |n, t| {
                        n.checked_add(t.fee).ok_or("INVALID_CONSENSUS reward sum")
                    })?;
                let reward = crate::kernel::hash(
                    "REWARD",
                    &[
                        &b[4..36],
                        &b[36..68],
                        &b[68..84],
                        &b[156..188],
                        &b[188..220],
                    ]
                    .concat(),
                );
                let mut outpoint = reward.to_vec();
                outpoint.extend(0u16.to_be_bytes());
                result.push(json!({"block_id":hex::encode(block_id(b)?),"height":height.to_string(),"transactions":txs.iter().map(|t|hex::encode(t.id)).collect::<Vec<_>>(),"reward":if amount>0{json!({"outpoint":hex::encode(outpoint),"amount":amount.to_string(),"maturity_height":(height+100).to_string()})}else{Value::Null}}));
            }
            Ok(result)
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
            json!({"previous_tip":hex::encode(before.tip().id()),"selected_tip":hex::encode(next.tip().id()),"previous_revision":revision.to_string(),"revision":(revision+1).to_string(),"state_root":hex::encode(next.tip().root()),"detached":entries(detached)?,"attached":entries(attached)?,"changed_outputs":changed,"confidence":"CONDITIONAL"}),
            detached.to_vec(),
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
        let location = self
            .observation_cache
            .borrow_mut()
            .location((self.ledger().tip().id(), self.revision()), id);
        if let Some((block, unsigned)) = location {
            for raw in transactions(&self.get_retained_block(block)?)? {
                let tx = decode_tx(&raw, self.ledger().chain_id())?;
                if tx.id == id && raw[..raw.len() - 64] == unsigned {
                    return Ok(raw);
                }
            }
            return Err(self.storage_fault("retained transaction observation binding"));
        }
        let mut stmt = self
            .db
            .prepare("SELECT id FROM blocks ORDER BY id")
            .map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            let block: Hash = row
                .get::<_, Vec<u8>>(0)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING block index")?;
            for x in transactions(&self.get_block(block)?)? {
                if decode_tx(&x, self.ledger().chain_id())?.id == id {
                    return Ok(x);
                }
            }
        }
        Err("MISSING_HISTORY transaction".into())
    }
    fn transfer_witness(&self, raw: &[u8], t: &Tx) -> Result<Witness> {
        if !self.storage_ready() {
            return Err("RESOURCE_WAIT restart required".into());
        }
        let anchor = (self.ledger().tip().id(), self.revision());
        let retained =
            self.observation_cache
                .borrow_mut()
                .get(anchor, t.id, &raw[..raw.len() - 64]);
        if let Some(w) = retained {
            // Re-read the exact retained proof objects, including the selected
            // head. A process-local witness cannot hide damage to those bytes.
            let proof: BTreeSet<_> = w
                .spends
                .values()
                .copied()
                .chain(w.location)
                .chain([anchor.0])
                .collect();
            for id in proof {
                if id != self.ledger().chain_id() {
                    self.get_retained_block(id)?;
                }
            }
            return Ok(w);
        }
        let selected = self.selected_ids()?;
        let mut inclusion = None;
        let mut spent = BTreeMap::new();
        for id in selected.iter().skip(1) {
            let b = self.get_block(*id)?;
            for x in transactions(&b)? {
                let tx = decode_tx(&x, self.ledger().chain_id())?;
                if tx.id == t.id {
                    inclusion = Some((*id, u128::from_be_bytes(b[68..84].try_into().unwrap())));
                }
                for input in tx.inputs {
                    if t.inputs.contains(&input) {
                        spent.insert(input, *id);
                    }
                }
            }
        }
        let mut detached = false;
        let mut location = inclusion.map(|(id, _)| id);
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
                            location = Some(id);
                        }
                    }
                    id = b[36..68].try_into().unwrap();
                }
            }
        }
        let witness = Witness {
            unsigned: raw[..raw.len() - 64].to_vec(),
            inputs: t.inputs.clone(),
            inclusion,
            spends: spent,
            ever_included: inclusion.is_some() || detached,
            location,
        };
        self.observation_cache
            .borrow_mut()
            .insert(anchor, t.id, witness.clone());
        Ok(witness)
    }
    pub fn transfer_observation(&self, raw: &[u8]) -> Result<Value> {
        let t = decode_tx(raw, self.ledger().chain_id())?;
        let witness = self.transfer_witness(raw, &t)?;
        let inclusion = witness.inclusion;
        let detached = witness.ever_included && inclusion.is_none();
        let selected_conflict = !witness.spends.is_empty();
        let local_conflict = inclusion.is_none()
            && !selected_conflict
            && self.ledger().validate_transfer(raw).is_ok()
            && self.pool_input_conflict(t.id)?;
        let reason = if inclusion.is_some() {
            None
        } else if self.ledger().tip().height() + 1 > t.expiry {
            Some("EXPIRED")
        } else if selected_conflict || local_conflict {
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
        let reserved = self.reservations()?;
        let outputs:Vec<_>=t.outputs.iter().enumerate().map(|(i,_)|{
            let mut key=t.id.to_vec();key.extend((i as u16).to_be_bytes());
            let coin=self.ledger().coins().get(&key);
            let maturity=coin.map(|c|c.maturity).or_else(||inclusion.map(|(_,h)|h));
            let eligible=coin.map(|c|c.maturity<=self.ledger().tip().height()+1).or_else(||inclusion.map(|_|false));
            json!({"outpoint":hex::encode(&key),"state":if coin.is_some(){"UNSPENT"}else if inclusion.is_some(){"SPENT"}else{"ABSENT"},"maturity_height":maturity.map(|h|h.to_string()),"eligible_next_height":eligible,"reserved":coin.is_some()&&reserved.contains(&key)})
        }).collect();
        Ok(
            json!({"transaction_id":hex::encode(t.id),"ledger":state,"readiness":reason,"conflict_source":if reason==Some("CONFLICTED"){Some(if selected_conflict{"SELECTED_HISTORY"}else{"LOCAL_POOL"})}else{None},"inclusion":inclusion.map(|(id,h)|json!({"block_id":hex::encode(id),"height":h.to_string(),"confirmations":(self.ledger().tip().height()-h+1).to_string()})),"outputs":outputs,"confidence":"CONDITIONAL"}),
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
        if let Some(review) = self.review_record(id)? {
            let u = review.unsigned;
            let x = review.signed;
            let waived = review.waived;
            let digest = review.digest;
            let (mut v, signature_source) = if let Some(x) = &x {
                (self.transfer_observation(x)?, Some("LOCAL_WALLET"))
            } else {
                let t = crate::kernel::decode_unsigned(&u, self.ledger().chain_id())?;
                match self.get_transaction(t.id) {
                    Ok(observed) => {
                        if observed.len() != u.len() + 64 || observed[..u.len()] != u {
                            return Err("INVALID_CRYPTO observed intent mismatch".into());
                        }
                        (
                            self.transfer_observation(&observed)?,
                            Some("RETAINED_PUBLIC_BYTES"),
                        )
                    }
                    Err(e) if e.starts_with("MISSING_HISTORY") => {
                        self.selected_ids()?;
                        let outputs:Vec<_>=t.outputs.iter().enumerate().map(|(i,_)|{
                            let mut id=t.id.to_vec();id.extend((i as u16).to_be_bytes());
                            json!({"outpoint":hex::encode(id),"state":"ABSENT","maturity_height":null,"eligible_next_height":null,"reserved":false})
                        }).collect();
                        (
                            json!({"transaction_id":hex::encode(t.id),"ledger":"UNSEEN","readiness":null,"inclusion":null,"outputs":outputs,"confidence":"CONDITIONAL"}),
                            None,
                        )
                    }
                    Err(e) => return Err(e),
                }
            };
            v["local_intent"] = json!(if waived {
                "WITHDRAWN"
            } else if x.is_some() {
                "SIGNED"
            } else {
                "REVIEWED"
            });
            v["transaction_hex"] = json!(x.map(hex::encode));
            v["signature_source"] = json!(signature_source);
            v["review_digest"] = json!(hex::encode(digest));
            v["reviewed_tip"] = json!(hex::encode(review.reviewed_tip));
            v["reviewed_revision"] = json!(review.reviewed_revision.to_string());
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

impl Store {
    pub fn pending_operation(&self, id: Hash) -> Result<Option<Value>> {
        type Pending = (Vec<u8>, Vec<u8>, Vec<u8>);
        let row: Option<Pending> = self
            .db
            .query_row(
                "SELECT prior_tip,prior_revision,raw FROM operations WHERE id=?1 AND committed=0",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(err)?;
        row.map(|(tip, revision, raw)| {
            let r = u128::from_be_bytes(revision.try_into().map_err(|_|"INVALID_ENCODING pending revision")?);
            let members: Option<Vec<u8>>=self.db.query_row("SELECT members FROM history_batches WHERE operation=?1",[id.as_slice()],|r|r.get(0)).optional().map_err(err)?;
            let history_members=members.as_ref().map(|b|b[2..].as_chunks::<32>().0.iter().map(hex::encode).collect::<Vec<_>>());
            Ok(json!({"state":"INTENT","prior_tip":hex::encode(&tip),"prior_revision":r.to_string(),"block_hex":hex::encode(raw),"history_members":history_members,"recovery_method":if members.is_some(){"accept_history"}else{"accept_block"},"prior_still_selected":tip==self.ledger().tip().id() && r==self.revision(),"first_signing":false}))
        }).transpose()
    }
}
