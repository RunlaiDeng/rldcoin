//! Native operation-fee inputs are reserved by persisted, fully native-reviewed
//! caller preparations. Delegated payment custody never authorizes these spends.
use super::*;
use crate::kernel::fast::planning::{Plan, Request};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnchainRequest {
    pub kind: u8,
    pub channel: Id,
    pub actor: Id,
    pub inputs: Vec<String>,
    pub fee: String,
    pub expiry: String,
    pub nonce: Id,
    pub certificate: String,
    pub timestamp: String,
}
pub(super) fn integer(s: &str) -> Result<u128> {
    ensure(
        !s.is_empty()
            && (s.len() == 1 || !s.starts_with('0'))
            && s.bytes().all(|c| c.is_ascii_digit()),
        "INVALID action integer",
    )?;
    s.parse()
        .map_err(|_| "INVALID action integer overflow".into())
}
impl OnchainRequest {
    fn reservation(&self) -> Result<Hash> {
        let mut exact = self.clone();
        exact.timestamp.clear();
        Ok(hash(
            "NATIVE-RESERVATION",
            &serde_json::to_vec(&exact).map_err(fast_retainer::io)?,
        ))
    }
    pub(super) fn request(&self) -> Result<Request> {
        ensure(
            (2..=5).contains(&self.kind) && (1..=32).contains(&self.inputs.len()),
            "INVALID native action kind/input count",
        )?;
        let inputs = self
            .inputs
            .iter()
            .map(|s| {
                let b = bytes(s, 34)?;
                ensure(b.len() == 34, "INVALID native action input size")?;
                Ok(b)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Request {
            kind: self.kind,
            channel: self.channel.0,
            actor: self.actor.0,
            inputs,
            fee: integer(&self.fee)?,
            expiry: integer(&self.expiry)?,
            nonce: self.nonce.0,
            certificate: bytes(&self.certificate, 252)?,
            timestamp: u64::try_from(integer(&self.timestamp)?)
                .map_err(|_| "INVALID action timestamp")?,
        })
    }
    fn review(&self, p: &Plan, tip: Hash) -> Value {
        json!({"chain_selected_tip":Id(tip),"kind":self.kind,"channel":self.channel,"spending_owner":self.actor,
            "inputs":self.inputs,"input_value":p.input_value.to_string(),"operation_fee":self.fee,"owner_change":p.change.to_string(),
            "expiry_height":self.expiry,"evaluation_timestamp":self.timestamp,"unsigned_operation_hex":hex::encode(p.unsigned()),
            "operation":match self.kind {2=>"CLOSE",3=>"PRINCIPAL_CHALLENGE",4=>"MINER_FEE_CLAIM",_=>"SETTLE"},
            "funding_miner":Id(p.miner),"authorized_principal":p.principal.map(|n|n.to_string()),
            "known_miner_fee_ranges":p.fee_ranges.map(|n|n.to_string()),"unused_fee_reserves":p.unused_reserves.map(|n|n.to_string()),
            "fixed_deadline_height":p.deadline_height.to_string(),"fixed_deadline_timestamp":p.deadline_time.to_string(),
            "ledger_admitted":false})
    }
}
pub struct MiningRequest {
    pub miner: Id,
    pub operations: Vec<String>,
    pub timestamp: String,
    pub attempts: u32,
}
impl Session {
    /// Retrieve already authenticated historical exit proof, including after
    /// close or reorganization. It never restores missing backing or signs.
    pub fn exit_evidence(&mut self, head: Hash, actor: Id, now: u64) -> Result<Value> {
        self.status(head, now)?;
        let state = self
            .actors
            .get(&actor)
            .ok_or("MISSING exit evidence actor")?;
        let child = Actor::open(
            &actor_path(&self.root, actor),
            self.chain,
            state.reg.role,
            state.head,
            now,
        )?;
        let (origin, _, _) = child.scope();
        let certificate = match child {
            Actor::Owner(mut j) => j
                .retained_complete(state.head)?
                .map(|(raw, _)| {
                    Payment::verify(&origin, &raw).map(|p| p.after_certificate().to_vec())
                })
                .transpose()?,
            Actor::Retainer(j) => j.latest_certificate().map(<[u8]>::to_vec),
        }
        .ok_or("MISSING retained complete exit certificate")?;
        let claim = origin.verify_certificate(&certificate)?;
        Ok(
            json!({"channel":Id(origin.channel()),"certificate_hex":hex::encode(certificate),"sequence":claim.sequence.to_string(),
            "miner":Id(origin.miner()),"backing_currentness_known":false,"ledger_admitted":false,"wallet_key_loaded":false,"fast_completion_authorized":false}),
        )
    }
    pub fn mining_candidate(
        &mut self,
        head: Hash,
        request: MiningRequest,
        now: u64,
    ) -> Result<Value> {
        self.caller.check(head)?;
        ensure(
            request.operations.len() <= 128 && (1..=4096).contains(&request.attempts),
            "RESOURCE_WAIT session mining request",
        )?;
        let timestamp =
            u64::try_from(integer(&request.timestamp)?).map_err(|_| "INVALID mining timestamp")?;
        let mut operations = request
            .operations
            .iter()
            .map(|s| bytes(s, 4096))
            .collect::<Result<Vec<_>>>()?;
        operations.sort_by_key(|op| fast::operation_id(op));
        let n = self
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT session native restart required")?;
        let tip = n.ledger().tip().id();
        n.check(n.head(), tip, now)?;
        if self.mining.as_ref().is_none_or(|job| {
            job.tip != tip
                || job.miner != request.miner.0
                || job.operations != operations
                || job.timestamp != timestamp
        }) {
            let job = n
                .ledger()
                .mining_job(request.miner.0, operations.clone(), timestamp, now)?;
            self.mining = Some(Mining {
                tip,
                miner: request.miner.0,
                operations,
                timestamp,
                job,
            });
        }
        let (block, calls) = self
            .mining
            .as_mut()
            .unwrap()
            .job
            .search(request.attempts as u64);
        if let Some(raw) = block {
            self.mining = None;
            self.candidate_output(raw, calls)
        } else {
            Ok(
                json!({"hash_calls":calls.to_string(),"candidate_only":true,"state":"SEARCH_PENDING","ledger_admitted":false}),
            )
        }
    }
    fn prepared(&self, before: usize, id: Id, review: Id) -> Result<(usize, OnchainRequest, Hash)> {
        let index = self.caller.ops[..before]
            .iter()
            .position(|o| o.intent.id == id)
            .ok_or("MISSING persisted native action review")?;
        let op = &self.caller.ops[index];
        let Action::OnchainPrepare { tip, plan } = &op.intent.action else {
            return Err("INVALID native action review type".into());
        };
        ensure(
            op.done.as_ref().is_some_and(|d| {
                d.review == Some(review) && d.effect.is_none() && d.authorization.is_none()
            }),
            "INVALID persisted native action review",
        )?;
        Ok((index, plan.clone(), tip.0))
    }
    pub(super) fn onchain_apply(
        &mut self,
        action: &Action,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<(Option<Id>, Option<Id>, Option<String>)> {
        match action {
            Action::OnchainPrepare { tip, plan } => {
                let n = self.native.as_mut().unwrap();
                let current = n.current(n.head(), tip.0, now)?;
                let prepared = current.ledger.plan_action(tip.0, &plan.request()?, now)?;
                Ok((None, Some(Id(prepared.review())), None))
            }
            Action::OnchainSign {
                tip,
                prepare_request,
                review,
                key_file,
                approved,
            } => {
                ensure(
                    *approved,
                    "INVALID explicit native action approval required",
                )?;
                let before = self.caller.ops.len() - 1;
                let (_, plan, original_tip) = self.prepared(before, *prepare_request, *review)?;
                ensure(
                    tip.0 == original_tip,
                    "INVALID native action changed review tip",
                )?;
                let n = self.native.as_mut().unwrap();
                let current = n.current(n.head(), tip.0, now)?;
                let prepared = current.ledger.plan_action(tip.0, &plan.request()?, now)?;
                ensure(
                    prepared.review() == review.0,
                    "INVALID stale native action review",
                )?;
                // A retained exact response can be reproduced without loading a key.
                for op in &self.caller.ops[..before] {
                    if matches!(&op.intent.action,Action::OnchainSign{prepare_request:p,..} if p==prepare_request)
                    {
                        if let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) {
                            prepared.verify_signed(&bytes(raw, 1589)?)?;
                            return Ok((None, None, Some(raw.clone())));
                        }
                    }
                }
                let key = load_key(Path::new(key_file), self.chain, password)?;
                let signed = prepared.sign(&key)?;
                Ok((None, None, Some(hex::encode(signed))))
            }
            _ => Err("INVALID on-chain action".into()),
        }
    }
    pub(super) fn onchain_preflight(&self, action: &Action) -> Result<()> {
        if let Action::OnchainPrepare { plan, .. } = action {
            let inputs = plan.request()?.inputs.into_iter().collect::<BTreeSet<_>>();
            for op in &self.caller.ops {
                if let Action::OnchainPrepare { plan: old, .. } = &op.intent.action {
                    if op.done.as_ref().is_some_and(|d| d.review.is_some()) {
                        ensure(
                            !old.request()?
                                .inputs
                                .iter()
                                .any(|input| inputs.contains(input))
                                || old.reservation()? == plan.reservation()?,
                            "CONFLICT native action input already reserved",
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
    pub(super) fn audit_onchain(&mut self, contexts: &[Hash]) -> Result<()> {
        ensure(
            contexts.len() == self.caller.ops.len(),
            "INVALID native audit context count",
        )?;
        let mut reserved = BTreeMap::new();
        let mut signatures = BTreeMap::<Id, String>::new();
        for (index, context) in contexts.iter().enumerate() {
            let op = self.caller.ops[index].clone();
            let Some(done) = &op.done else { continue };
            if index < self.onchain_audited {
                // Caller/native file identity and complete retained bytes were
                // rechecked by audit before reaching this private witness. Cold
                // opening always starts at zero and performs full native replay.
                match &op.intent.action {
                    Action::OnchainPrepare { plan, .. } if done.review.is_some() => {
                        let binding = plan.reservation()?;
                        for input in plan.request()?.inputs {
                            reserved.insert(input, binding);
                        }
                    }
                    Action::OnchainSign {
                        prepare_request, ..
                    } => {
                        if let Some(raw) = &done.authorization {
                            signatures.insert(*prepare_request, raw.clone());
                        }
                    }
                    _ => {}
                }
                continue;
            }
            match &op.intent.action {
                Action::OnchainPrepare { tip, plan } => {
                    ensure(
                        done.effect.is_none() && done.authorization.is_none(),
                        "INVALID native preparation effect",
                    )?;
                    if let Some(review) = done.review {
                        ensure(tip.0 == *context, "INVALID prepared native selection")?;
                        let request = plan.request()?;
                        let ledger = self.native.as_mut().unwrap().historical(tip.0)?;
                        let native = ledger.plan_action(tip.0, &request, op.intent.at)?;
                        ensure(
                            native.review() == review.0,
                            "INVALID native preparation review",
                        )?;
                        let binding = plan.reservation()?;
                        for input in request.inputs {
                            if let Some(old) = reserved.insert(input, binding) {
                                ensure(
                                    old == binding,
                                    "INVALID overlapping native action reservation",
                                )?;
                            }
                        }
                    }
                }
                Action::OnchainSign {
                    tip,
                    prepare_request,
                    review,
                    approved,
                    ..
                } => {
                    ensure(
                        done.effect.is_none() && done.review.is_none(),
                        "INVALID native signature child effect",
                    )?;
                    if let Some(raw) = &done.authorization {
                        ensure(
                            *approved && tip.0 == *context,
                            "INVALID native signature consent/selection",
                        )?;
                        let (_, plan, original) =
                            self.prepared(index, *prepare_request, *review)?;
                        ensure(original == tip.0, "INVALID native signature original tip")?;
                        let ledger = self.native.as_mut().unwrap().historical(tip.0)?;
                        let native = ledger.plan_action(tip.0, &plan.request()?, op.intent.at)?;
                        ensure(
                            native.review() == review.0,
                            "INVALID native signature stale review",
                        )?;
                        native.verify_signed(&bytes(raw, 1589)?)?;
                        if let Some(old) = signatures.insert(*prepare_request, raw.clone()) {
                            ensure(old == *raw, "INVALID replaced native authorization")?;
                        }
                    }
                }
                _ => ensure(
                    done.authorization.is_none(),
                    "INVALID unrelated native authorization field",
                )?,
            }
        }
        Ok(())
    }
    pub(super) fn onchain_output(
        &mut self,
        action: &Action,
        done: &Done,
        at: u64,
    ) -> Result<Option<Value>> {
        if let Action::OnchainPrepare { tip, plan } = action {
            if done.review.is_some() {
                let ledger = self.native.as_mut().unwrap().historical(tip.0)?;
                let native = ledger.plan_action(tip.0, &plan.request()?, at)?;
                return Ok(Some(plan.review(&native, tip.0)));
            }
        }
        Ok(None)
    }
}
