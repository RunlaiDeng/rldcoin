//! Native operation-fee inputs are reserved by persisted, fully native-reviewed
//! caller preparations. Delegated payment custody never authorizes these spends.
use super::transfer::Preparation;
use super::*;
use crate::kernel::fast::planning::{Plan, Request};
use std::collections::BTreeSet;

/// One immutable, fully reconstructed context during one caller audit only.
/// Never serialized, supplied by a peer or used to initialize a native store.
pub(super) struct HistoricalAudit {
    caller: Hash,
    caller_head: Hash,
    native_head: Hash,
    source: usize,
    last: Option<(Hash, fast::Ledger)>,
    #[cfg(test)]
    replays: usize,
}

#[cfg(test)]
mod historical_tests {
    // PUBLIC NO-VALUE unit fixture keys only; never monetary custody.
    use super::*;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    fn fixture() -> (Session, Vec<Vec<u8>>, PathBuf, u64) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let v: Value = serde_json::from_str(include_str!(
            "../../../../docs/protocol/native-fast-escrow-v1-vectors.json"
        ))
        .unwrap();
        let mut g = hex::decode(v["genesis_hex"].as_str().unwrap()).unwrap();
        getrandom::getrandom(&mut g[13..45]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        g[45..53].copy_from_slice(&(now - 7200).to_be_bytes());
        let chain = fast::genesis_id(&g);
        let root = std::env::temp_dir().join(format!(
            "rld-historical-audit-{}-{}",
            std::process::id(),
            hex::encode(chain)
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut s = Session::create(&root.join("node"), &g, chain, now).unwrap();
        let mut ledger = fast::Ledger::from_genesis(&g, chain, 100000).unwrap();
        let miner = ed25519_dalek::SigningKey::from_bytes(&[141; 32])
            .verifying_key()
            .to_bytes();
        let mut blocks = vec![];
        for n in 1..=2 {
            let mut job = ledger
                .mining_job(miner, vec![], ledger.tip().timestamp() + 600, now)
                .unwrap();
            let raw = loop {
                assert!(Instant::now() < deadline);
                if let (Some(raw), _) = job.search(4096) {
                    break raw;
                }
            };
            ledger.execute(&raw, now).unwrap();
            let out = s
                .execute(
                    Id([n; 32]),
                    s.head(),
                    Action::Native {
                        tip: Id(s.tip()),
                        block: hex::encode(&raw),
                    },
                    None,
                    now,
                )
                .unwrap();
            assert!(out["diagnostic"].is_null());
            blocks.push(raw);
        }
        (s, blocks, root, now)
    }
    #[test]
    fn audit_local_context_replays_each_exact_tip_and_cold_audits_start_empty() {
        let (mut s, blocks, root, now) = fixture();
        let first = fast::block_id(&blocks[0]).unwrap();
        let mut audit = s.historical_audit();
        assert!(audit.last.is_none());
        assert_eq!(s.audit_ledger(&mut audit, first).unwrap().tip().height(), 1);
        assert_eq!(audit.replays, 1);
        assert_eq!(s.audit_ledger(&mut audit, first).unwrap().tip().id(), first);
        assert_eq!(
            audit.replays, 1,
            "reuse still requires the actual source prefix checks"
        );
        let selected = s.tip();
        assert_eq!(
            s.audit_ledger(&mut audit, selected).unwrap().tip().height(),
            2
        );
        assert_eq!(audit.replays, 2);
        assert_eq!(s.audit_ledger(&mut audit, first).unwrap().tip().height(), 1);
        assert_eq!(audit.replays, 3, "only one context may remain retained");
        let head = s.head();
        let genesis = s.genesis.clone();
        let chain = s.chain;
        drop(s);
        drop(audit);
        let mut cold = Session::open(&root.join("node"), &genesis, chain, head, now).unwrap();
        let mut fresh = cold.historical_audit();
        assert!(fresh.last.is_none());
        assert_eq!(fresh.replays, 0);
        assert_eq!(
            cold.audit_ledger(&mut fresh, first).unwrap().tip().height(),
            1
        );
        assert_eq!(fresh.replays, 1);
    }
    #[test]
    fn audit_local_context_rejects_another_live_store_and_changed_actual_bytes() {
        let (mut s, blocks, root, now) = fixture();
        let first = fast::block_id(&blocks[0]).unwrap();
        let mut audit = s.historical_audit();
        s.audit_ledger(&mut audit, first).unwrap();
        let mut foreign = Session::create(&root.join("foreign"), &s.genesis, s.chain, now).unwrap();
        for (n, raw) in blocks.iter().enumerate() {
            let out = foreign
                .execute(
                    Id([n as u8 + 1; 32]),
                    foreign.head(),
                    Action::Native {
                        tip: Id(foreign.tip()),
                        block: hex::encode(raw),
                    },
                    None,
                    now,
                )
                .unwrap();
            assert!(out["diagnostic"].is_null());
        }
        assert_eq!(s.caller.binding(), foreign.caller.binding());
        assert_eq!(s.head(), foreign.head());
        assert_eq!(s.native_head(), foreign.native_head());
        assert!(foreign
            .audit_ledger(&mut audit, first)
            .err()
            .unwrap()
            .contains("source instance"));
        let path = root.join("node/native.journal");
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(&path, &raw).unwrap();
        assert!(s.audit_ledger(&mut audit, first).is_err());
        assert!(!s.native.as_ref().unwrap().storage_ready());
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert_eq!(audit.replays, 1);
    }
}

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
    pub(super) fn reservation(&self) -> Result<Hash> {
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
    pub(super) fn review(&self, p: &Plan, tip: Hash) -> Value {
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
    pub(super) fn prepared(
        &self,
        before: usize,
        id: Id,
        review: Id,
    ) -> Result<(usize, Preparation, Hash)> {
        let index = self.caller.ops[..before]
            .iter()
            .position(|o| o.intent.id == id)
            .ok_or("MISSING persisted native action review")?;
        let op = &self.caller.ops[index];
        let (tip, plan) = op
            .intent
            .action
            .preparation()
            .ok_or("INVALID native action review type")?;
        ensure(
            op.done.as_ref().is_some_and(|d| {
                d.review == Some(review) && d.effect.is_none() && d.authorization.is_none()
            }),
            "INVALID persisted native action review",
        )?;
        Ok((index, plan, tip))
    }
    pub(super) fn onchain_apply(
        &mut self,
        action: &Action,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<(Option<Id>, Option<Id>, Option<String>)> {
        if matches!(
            action,
            Action::FeePolicyApprove { .. } | Action::FeePolicySign { .. }
        ) {
            return Ok((None, None, self.fee_apply(action, password, now)?));
        }
        if let Some((tip, plan)) = action.preparation() {
            if let Action::FeePolicyPrepare { policy_request, .. } = action {
                self.fee_prepare_time(*policy_request, tip, now)?;
            }
            let n = self.native.as_mut().unwrap();
            let current = n.current(n.head(), tip, now)?;
            let prepared = plan.evaluate(current.ledger, tip, now)?;
            return Ok((None, Some(Id(prepared.review())), None));
        }
        match action {
            Action::OpenCombine { .. } => {
                let raw = self.combine_opening(self.caller.ops.len() - 1, action, now, true)?;
                Ok((None, Some(Id(fast::operation_id(&raw))), None))
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
                let prepared = plan.evaluate(current.ledger, tip.0, now)?;
                ensure(
                    prepared.review() == review.0,
                    "INVALID stale native action review",
                )?;
                // A retained exact response can be reproduced without loading a key.
                for op in &self.caller.ops[..before] {
                    if matches!(&op.intent.action,Action::OnchainSign{prepare_request:p,..} if p==prepare_request)
                    {
                        if let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) {
                            prepared.verify_signed(&bytes(raw, 4096)?)?;
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
        if let Some((_, plan)) = action.preparation() {
            let inputs = plan.inputs()?.into_iter().collect::<BTreeSet<_>>();
            for op in &self.caller.ops {
                if let Some((_, old)) = op.intent.action.preparation() {
                    if op.done.as_ref().is_some_and(|d| d.review.is_some()) {
                        ensure(
                            !old.inputs()?.iter().any(|input| inputs.contains(input))
                                || old.reservation()? == plan.reservation()?,
                            "CONFLICT native action input already reserved",
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
    fn historical_audit(&self) -> HistoricalAudit {
        let native = self.native.as_ref().unwrap();
        HistoricalAudit {
            caller: self.caller.binding(),
            caller_head: self.caller.head,
            native_head: native.head(),
            source: std::ptr::from_ref(native) as usize,
            last: None,
            #[cfg(test)]
            replays: 0,
        }
    }
    pub(super) fn audit_ledger<'a>(
        &mut self,
        audit: &'a mut HistoricalAudit,
        tip: Hash,
    ) -> Result<&'a fast::Ledger> {
        ensure(
            audit.caller == self.caller.binding(),
            "INVALID historical audit caller binding",
        )?;
        self.caller.check(audit.caller_head)?;
        let native = self
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT historical native restart")?;
        ensure(
            audit.source == std::ptr::from_ref(native) as usize,
            "INVALID historical audit source instance",
        )?;
        native.check_history_source(audit.native_head)?;
        if audit.last.as_ref().is_none_or(|(old, _)| *old != tip) {
            // Release the old context before reconstructing another: at most
            // one temporary historical ledger, under the original native caps.
            audit.last = None;
            let ledger = native.historical(tip)?;
            audit.last = Some((tip, ledger));
            #[cfg(test)]
            {
                audit.replays += 1;
            }
        }
        Ok(&audit.last.as_ref().unwrap().1)
    }
    pub(super) fn audit_onchain(&mut self, contexts: &[Hash]) -> Result<()> {
        ensure(
            contexts.len() == self.caller.ops.len(),
            "INVALID native audit context count",
        )?;
        let mut reserved = BTreeMap::new();
        let mut signatures = BTreeMap::<Id, String>::new();
        let mut historical = self.historical_audit();
        for (index, context) in contexts.iter().enumerate() {
            let op = self.caller.ops[index].clone();
            let Some(done) = &op.done else { continue };
            if index < self.onchain_audited {
                // Caller/native file identity and complete retained bytes were
                // rechecked by audit before reaching this private witness. Cold
                // opening always starts at zero and performs full native replay.
                if let Some((_, plan)) = op.intent.action.preparation() {
                    if done.review.is_some() {
                        let binding = plan.reservation()?;
                        for input in plan.inputs()? {
                            reserved.insert(input, binding);
                        }
                    }
                }
                if let Action::OnchainSign {
                    prepare_request, ..
                } = &op.intent.action
                {
                    if let Some(raw) = &done.authorization {
                        signatures.insert(*prepare_request, raw.clone());
                    }
                }
                continue;
            }
            if self.audit_fee_step(index, *context, &mut historical)? {
                continue;
            }
            if let Some((tip, plan)) = op.intent.action.preparation() {
                ensure(
                    done.effect.is_none() && done.authorization.is_none(),
                    "INVALID native preparation effect",
                )?;
                if let Some(review) = done.review {
                    ensure(tip == *context, "INVALID prepared native selection")?;
                    let ledger = self.audit_ledger(&mut historical, tip)?;
                    // Use this same complete native reconstruction for policy
                    // time and value review. Neither condition may be omitted.
                    if let Action::FeePolicyPrepare { policy_request, .. } = &op.intent.action {
                        let (_, policy) = self.policy(index, *policy_request)?;
                        policy.time(ledger.tip().height(), op.intent.at)?;
                    }
                    let native = plan.evaluate(ledger, tip, op.intent.at)?;
                    ensure(
                        native.review() == review.0,
                        "INVALID native preparation review",
                    )?;
                    let binding = plan.reservation()?;
                    for input in plan.inputs()? {
                        if let Some(old) = reserved.insert(input, binding) {
                            ensure(
                                old == binding,
                                "INVALID overlapping native action reservation",
                            )?;
                        }
                    }
                }
                continue;
            }
            match &op.intent.action {
                Action::OpenCombine { tip, .. } => {
                    // This separate complete closure verifier owns its own
                    // historical reconstruction; retain no second context.
                    historical.last = None;
                    ensure(
                        done.effect.is_none() && done.authorization.is_none(),
                        "INVALID opening combination effect",
                    )?;
                    if let Some(expected) = done.review {
                        ensure(tip.0 == *context, "INVALID opening combination selection")?;
                        let raw =
                            self.combine_opening(index, &op.intent.action, op.intent.at, false)?;
                        ensure(
                            fast::operation_id(&raw) == expected.0,
                            "INVALID opening combination commitment",
                        )?;
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
                        let ledger = self.audit_ledger(&mut historical, tip.0)?;
                        let native = plan.evaluate(ledger, tip.0, op.intent.at)?;
                        ensure(
                            native.review() == review.0,
                            "INVALID native signature stale review",
                        )?;
                        native.verify_signed(&bytes(raw, 4096)?)?;
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
        if let Some((tip, plan)) = action.preparation() {
            if done.review.is_some() {
                let ledger = self.native.as_mut().unwrap().historical(tip)?;
                let native = plan.evaluate(&ledger, tip, at)?;
                return Ok(Some(plan.review_json(&native, tip)?));
            }
        }
        Ok(None)
    }
}
