//! Bounded custody of existing signatures. No pool row, data receipt or
//! candidate grants a ledger output, first signature or owner-input release.
use super::*;
const COUNT: usize = 512;
const BYTES: usize = 2 * 1024 * 1024;
struct Entry {
    id: Hash,
    raw: Vec<u8>,
    at: u64,
}
pub struct PoolMiningRequest {
    pub miner: Id,
    pub timestamp: String,
    pub attempts: u32,
    pub scan_limit: u16,
    pub refresh: bool,
}
pub(super) struct PoolMining {
    work: Mining,
    view: Value,
}
impl Session {
    pub(super) fn carriage_pool(&self) -> Result<Vec<(Hash, Vec<u8>)>> {
        Ok(self
            .pool_entries()?
            .into_iter()
            .map(|e| (e.id, e.raw))
            .collect())
    }
    pub(super) fn pool_binding(&self) -> Result<Hash> {
        Ok(hash(
            "POOL-CONTENTS",
            &self
                .pool_entries()?
                .into_iter()
                .flat_map(|e| e.id)
                .collect::<Vec<_>>(),
        ))
    }
    fn pool_entries(&self) -> Result<Vec<Entry>> {
        let mut result = Vec::<Entry>::new();
        let mut ids = BTreeMap::<Hash, usize>::new();
        let mut size = 0;
        for op in &self.caller.ops {
            if let Action::PoolSubmit { operation, .. } = &op.intent.action {
                let Some(done) = &op.done else { continue };
                if done.diagnostic.is_some() {
                    continue;
                }
                let raw = bytes(operation, 4096)?;
                fast::validate_operation(&raw, self.chain)?;
                let id = fast::operation_id(&raw);
                if let Some(index) = ids.get(&id) {
                    ensure(
                        result[*index].raw == raw,
                        "INVALID pool operation identity collision",
                    )?;
                    continue;
                }
                size += raw.len();
                ensure(
                    result.len() < COUNT && size <= BYTES,
                    "RESOURCE_WAIT pool retained capacity",
                )?;
                ids.insert(id, result.len());
                result.push(Entry {
                    id,
                    raw,
                    at: op.intent.at,
                });
            }
        }
        Ok(result)
    }
    pub(super) fn pool_preflight(&self, action: &Action) -> Result<()> {
        if let Action::PoolSubmit { operation, .. } = action {
            let raw = bytes(operation, 4096)?;
            fast::validate_operation(&raw, self.chain)?;
            let entries = self.pool_entries()?;
            let id = fast::operation_id(&raw);
            if let Some(entry) = entries.iter().find(|e| e.id == id) {
                ensure(entry.raw == raw, "INVALID changed pool duplicate")?;
            } else {
                ensure(
                    entries.len() < COUNT
                        && entries.iter().map(|e| e.raw.len()).sum::<usize>() + raw.len() <= BYTES,
                    "RESOURCE_WAIT pool retained capacity",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn audit_pool(&self, contexts: &[Hash]) -> Result<()> {
        for (index, op) in self.caller.ops.iter().enumerate() {
            if let Action::PoolSubmit { tip, operation } = &op.intent.action {
                fast::validate_operation(&bytes(operation, 4096)?, self.chain)?;
                if let Some(done) = &op.done {
                    ensure(
                        done.effect.is_none()
                            && done.review.is_none()
                            && done.authorization.is_none(),
                        "INVALID pool caller effect",
                    )?;
                    if done.diagnostic.is_none() {
                        ensure(
                            tip.0 == contexts[index],
                            "INVALID pool native selection binding",
                        )?;
                    }
                }
            }
        }
        self.pool_entries()?;
        Ok(())
    }
    pub fn submit_authorized(
        &mut self,
        head: Hash,
        request: Id,
        sign_request: Id,
        now: u64,
    ) -> Result<Value> {
        self.caller.check(head)?;
        let index = self
            .caller
            .ops
            .iter()
            .position(|op| op.intent.id == sign_request)
            .ok_or("MISSING retained signing request")?;
        let raw = self.retained_authorization(index)?;
        let id = fast::operation_id(&raw);
        let mut v = self.execute(
            request,
            head,
            Action::PoolSubmit {
                tip: Id(self.tip()),
                operation: hex::encode(raw),
            },
            None,
            now,
        )?;
        if v["diagnostic"].is_null() {
            v["pool_operation"] = serde_json::to_value(Id(id)).map_err(fast_retainer::io)?;
        }
        Ok(v)
    }
    pub fn pool_operation(&mut self, head: Hash, id: Id, now: u64) -> Result<Vec<u8>> {
        self.status(head, now)?;
        self.pool_entries()?
            .into_iter()
            .find(|e| e.id == id.0)
            .map(|e| e.raw)
            .ok_or("MISSING retained pool operation".into())
    }
    pub fn retained_block(&mut self, head: Hash, id: Id, now: u64) -> Result<Vec<u8>> {
        self.status(head, now)?;
        Ok(self.native.as_ref().unwrap().block(id.0)?.to_vec())
    }
    pub fn pool_status(&mut self, head: Hash, now: u64) -> Result<Value> {
        self.status(head, now)?;
        let entries = self.pool_entries()?;
        let wanted = entries.iter().map(|e| (e.id, e.raw.clone())).collect();
        let included = self
            .native
            .as_mut()
            .unwrap()
            .pool_inclusions(&wanted, now)?;
        let mut rows = vec![];
        for e in entries {
            let age = now.checked_sub(e.at).ok_or("CLOCK_WAIT pool observation")?;
            let inclusion = included.get(&e.id);
            rows.push(json!({"operation":Id(e.id),"local_first_queued_at":e.at.to_string(),"local_age_seconds":age.to_string(),
                "state":if inclusion.is_some(){"INCLUDED"}else{"RETAINED"},"selected_block":inclusion.map(|(id,_)|Id(*id)),"selected_height":inclusion.map(|(_,h)|h.to_string()),
                "native_inclusion_known":true,"eligible_for_next_block":Value::Null,"maturity_known":false}));
        }
        Ok(
            json!({"operations":rows,"conditional_selected_history":true,"fast_completion_authorized":false,"independent_freshness":false}),
        )
    }
    pub fn mine_pool(&mut self, head: Hash, request: PoolMiningRequest, now: u64) -> Result<Value> {
        self.caller.check(head)?;
        ensure(
            (1..=4096).contains(&request.attempts) && (1..=128).contains(&request.scan_limit),
            "RESOURCE_WAIT pool mining work bound",
        )?;
        let timestamp = u64::try_from(super::onchain::integer(&request.timestamp)?)
            .map_err(|_| "INVALID pool timestamp")?;
        let tip = self.tip();
        let n = self
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT native restart required")?;
        n.check(n.head(), tip, now)?;
        let replace = request.refresh
            || self.pool_mining.as_ref().is_none_or(|j| {
                j.work.tip != tip
                    || j.work.miner != request.miner.0
                    || j.work.timestamp != timestamp
            });
        if replace {
            let entries = self.pool_entries()?;
            let wanted = entries.iter().map(|e| (e.id, e.raw.clone())).collect();
            let n = self.native.as_mut().unwrap();
            let included = n.pool_inclusions(&wanted, now)?;
            n.ledger()
                .mining_job(request.miner.0, vec![], timestamp, now)?;
            let mut selected = vec![];
            let mut considered = 0usize;
            let mut deferred = vec![];
            let mut ids = vec![];
            for _ in 0..usize::from(request.scan_limit).min(entries.len()) {
                self.pool_cursor %= entries.len();
                let e = &entries[self.pool_cursor];
                self.pool_cursor = (self.pool_cursor + 1) % entries.len();
                considered += 1;
                if included.contains_key(&e.id) {
                    continue;
                }
                let mut candidate = selected.clone();
                candidate.push(e.raw.clone());
                match n
                    .ledger()
                    .mining_job(request.miner.0, candidate.clone(), timestamp, now)
                {
                    Ok(_) => {
                        selected = candidate;
                        ids.push(Id(e.id));
                    }
                    Err(mut diagnostic) => {
                        diagnostic.truncate(256);
                        deferred.push(json!({"operation":Id(e.id),"diagnostic":diagnostic}));
                    }
                }
            }
            let job = n
                .ledger()
                .mining_job(request.miner.0, selected.clone(), timestamp, now)?;
            let view = json!({"considered":considered,"retained":entries.len(),"unscanned":entries.len()-considered,"selected_operations":ids,"deferred":deferred});
            self.pool_mining = Some(PoolMining {
                work: Mining {
                    tip,
                    miner: request.miner.0,
                    operations: selected,
                    timestamp,
                    job,
                },
                view,
            });
        }
        let job = self.pool_mining.as_mut().unwrap();
        let view = job.view.clone();
        let (block, calls) = job.work.job.search(request.attempts as u64);
        if let Some(raw) = block {
            self.pool_mining = None;
            let mut v = self.candidate_output(raw, calls)?;
            v["pool_template"] = view;
            Ok(v)
        } else {
            Ok(
                json!({"state":"SEARCH_PENDING","hash_calls":calls.to_string(),"candidate_only":true,"ledger_admitted":false,"pool_template":view}),
            )
        }
    }
    pub(super) fn candidate_output(&mut self, raw: Vec<u8>, calls: u64) -> Result<Value> {
        let id = fast::block_id(&raw)?;
        let block = hex::encode(&raw);
        let action = Action::Native {
            tip: Id(self.tip()),
            block: block.clone(),
        };
        ensure(
            raw[36..68] == self.tip(),
            "INVALID candidate current parent",
        )?;
        let digest = action.digest()?;
        self.candidate = Some(raw);
        Ok(
            json!({"candidate":Id(id),"block_hex":block,"hash_calls":calls.to_string(),"admission_request_digest":digest,"candidate_only":true,"ledger_admitted":false}),
        )
    }
    pub fn admit_candidate(
        &mut self,
        head: Hash,
        request: Id,
        candidate: Id,
        now: u64,
    ) -> Result<Value> {
        self.caller.check(head)?;
        let raw = self
            .candidate
            .as_ref()
            .ok_or("MISSING process-local candidate")?
            .clone();
        ensure(
            fast::block_id(&raw)? == candidate.0 && raw[36..68] == self.tip(),
            "INVALID stale or different candidate",
        )?;
        let mut v = self.execute(
            request,
            head,
            Action::Native {
                tip: Id(self.tip()),
                block: hex::encode(raw),
            },
            None,
            now,
        )?;
        if v["diagnostic"].is_null() {
            v["admitted_candidate"] = serde_json::to_value(candidate).map_err(fast_retainer::io)?;
            v["candidate_selected"] = (self.tip() == candidate.0).into();
        }
        Ok(v)
    }
}
