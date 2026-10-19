//! Explicitly activated local service. Native execution and retained signed fee
//! consent remain the only spending authority; runtime observations are not one.
use super::*;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    pub policy_request: Id,
    pub key_file: String,
    pub operation_fee: String,
}
pub struct FeeMonitor {
    config: MonitorConfig,
    binding: Hash,
    password: Option<Zeroizing<Vec<u8>>>,
    last_at: Option<u64>,
    last: Option<Value>,
    diagnostic: Option<String>,
    cursor: usize,
}
fn timestamp(s: &Session, now: u64) -> Result<u64> {
    let parent = s
        .native
        .as_ref()
        .ok_or("RESOURCE_WAIT native restart required")?
        .ledger()
        .tip()
        .timestamp();
    let next = parent
        .checked_add(1)
        .ok_or("CLOCK_WAIT native timestamp overflow")?;
    Ok(parent.saturating_add(600).min(now).max(next))
}
fn checked(v: Value) -> Result<Value> {
    if let Some(error) = v["diagnostic"].as_str() {
        Err(error.to_string())
    } else {
        Ok(v)
    }
}
fn request(s: &Session, label: &str, raw: &[u8]) -> Id {
    Id(hash(
        label,
        &[s.chain.as_slice(), &s.caller.binding(), &s.head(), raw].concat(),
    ))
}
impl FeeMonitor {
    /// Private operator activation, not a new owner approval. A password unlocks
    /// only the already signed policy. It is never serialized or echoed.
    pub fn start(
        s: &mut Session,
        head: Hash,
        config: MonitorConfig,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<Self> {
        s.status(head, now)?;
        ensure(
            s.controlled(),
            "UNSUPPORTED monitor requires trusted caller control",
        )?;
        let state = s.policy_state(s.caller.ops.len(), config.policy_request)?;
        let fee = onchain::integer(&config.operation_fee)?;
        ensure(
            fee > 0 && fee <= onchain::integer(&state.terms.max_fee)?,
            "INVALID monitor operation fee",
        )?;
        if password.is_some() {
            state
                .terms
                .time(s.native.as_ref().unwrap().ledger().tip().height(), now)?;
        }
        // Authenticate available custody before opening even a fee-wallet key.
        for channel in &state.terms.channels {
            s.monitor_proofs(*channel, now)?;
        }
        let password = if let Some(p) = password {
            ensure(
                (1..=1024).contains(&p.len()),
                "INVALID monitor password bound",
            )?;
            let key = load_key(Path::new(&config.key_file), s.chain, Some(p))?;
            ensure(
                key.verifying_key().to_bytes() == state.terms.owner.0,
                "INVALID monitor fee-wallet key",
            )?;
            Some(Zeroizing::new(p.to_vec()))
        } else {
            None
        };
        Ok(Self {
            config,
            binding: s.caller.binding(),
            password,
            last_at: None,
            last: None,
            diagnostic: None,
            cursor: 0,
        })
    }
    pub fn status(&self) -> Value {
        json!({"active":true,"fee_key_unlocked":self.password.is_some(),"policy_request":self.config.policy_request,
            "last_observed_at":self.last_at.map(|n|n.to_string()),"last_observation":self.last,"diagnostic":self.diagnostic,
            "observation_current":self.diagnostic.is_none() && self.last.is_some(),
            "automatic_carriage":false,"independent_freshness":false,"fast_completion_authorized":false})
    }
    /// One channel per tick; at most one prepare/sign/pool sequence. A stopped
    /// or restarted process has no monitor and no retained unlock secret.
    pub fn tick(&mut self, s: &mut Session, now: u64) -> Result<()> {
        let result = self.step(s, now);
        match &result {
            Ok(v) => {
                self.last = Some(v.clone());
                self.last_at = Some(now);
                self.diagnostic = None;
            }
            Err(e) => self.diagnostic = Some(e.clone()),
        }
        result.map(|_| ())
    }
    fn step(&mut self, s: &mut Session, now: u64) -> Result<Value> {
        ensure(
            self.last_at.is_none_or(|at| now >= at),
            "CLOCK_WAIT monitor observation rollback",
        )?;
        s.status(s.head(), now)?;
        ensure(
            s.controlled() && s.caller.binding() == self.binding,
            "INVALID monitor caller binding",
        )?;
        let state = s.policy_state(s.caller.ops.len(), self.config.policy_request)?;
        let channel = state.terms.channels[self.cursor % state.terms.channels.len()];
        self.cursor = (self.cursor + 1) % state.terms.channels.len();
        let at = timestamp(s, now)?;
        let ledger = s.native.as_ref().unwrap().ledger();
        if state.terms.time(ledger.tip().height(), now).is_err() {
            self.password = None;
        }
        let proofs = s.monitor_proofs(channel, now)?;
        let ledger = s.native.as_ref().unwrap().ledger();
        let watch = match ledger.fee_watch(channel.0, at, now) {
            Ok(w) => w,
            Err(e) if e == "MISSING fast escrow" => return s.monitor_settlement(channel, now),
            Err(e) => return Err(e),
        };
        let mut row = json!({"channel":channel,"selected_tip":Id(s.tip()),"observed_at":now.to_string(),
            "prospective_block_timestamp":at.to_string(),"principal_sequence":watch.principal_sequence.to_string(),
            "fee_slots":watch.slots.map(|n|n.to_string()),"fixed_deadline_height":watch.deadline_height.map(|n|n.to_string()),
            "fixed_deadline_timestamp":watch.deadline_time.map(|n|n.to_string()),"protected_certificates":proofs.len(),
            "conditional_selected_history":true,"native_inclusion_known":true,"phase":"OPEN"});
        if !watch.closing {
            return Ok(row);
        }
        if proofs.is_empty() {
            row["phase"] = json!("NO_PROTECTED_CUSTODY");
            return Ok(row);
        }
        let origin = ledger.funding_origin(channel.0)?;
        let mut claims = BTreeMap::new();
        for raw in proofs {
            let claim = origin.verify_certificate(&raw)?;
            if let Some((old, _)) = claims.get(&claim.sequence) {
                ensure(
                    *old == claim,
                    "CONFLICT monitor joint states at same sequence",
                )?;
            }
            claims.insert(claim.sequence, (claim, raw));
        }
        let (_, (highest, principal)) = claims.last_key_value().unwrap();
        ensure(
            highest.sequence != watch.principal_sequence
                || highest.balances == watch.principal_balances,
            "CONFLICT monitor retained and native principal at same sequence",
        )?;
        let mut kind = 0;
        let mut proof = vec![];
        if highest.sequence > watch.principal_sequence {
            kind = 3;
            proof = principal.clone();
        }
        if kind == 0 {
            if let Some((_, raw)) = claims
                .values()
                .find(|(c, _)| (0..2).any(|i| c.slots[i] > watch.slots[i]))
            {
                kind = 4;
                proof = raw.clone();
            }
        }
        if watch.settlement_eligible {
            if kind != 0 {
                row["phase"] = json!("MISSED_PROTECTION_WINDOW");
                return Ok(row);
            }
            kind = 5;
        } else if kind == 0 {
            row["phase"] = json!("PROTECTED_WAITING_WINDOW");
            return Ok(row);
        }
        // An already retained valid signature needs no key or second allowance.
        if let Some((sign, raw)) =
            s.monitor_existing(self.config.policy_request, channel, kind, &proof, at, now)?
        {
            s.monitor_submit(sign, &raw, now)?;
            row["phase"] = json!("SIGNED_WAITING_NATIVE_INCLUSION");
            row["operation"] = json!(Id(fast::operation_id(&raw)));
            row["operation_included"] = json!(false);
            return Ok(row);
        }
        state.terms.time(ledger_height(s), now)?;
        let Some(password) = self.password.as_ref() else {
            row["phase"] = json!("LOCKED");
            return Ok(row);
        };
        let plan = s.monitor_plan(
            &state,
            self.config.policy_request,
            channel,
            kind,
            proof,
            &self.config.operation_fee,
            at,
            now,
        )?;
        let prep = request(s, "AUTO-FEE-PREPARE", &plan.nonce.0);
        let prepared = checked(s.execute(
            prep,
            s.head(),
            Action::FeePolicyPrepare {
                tip: Id(s.tip()),
                policy_request: self.config.policy_request,
                plan,
            },
            None,
            now,
        )?)?;
        let review: Id =
            serde_json::from_value(prepared["review_digest"].clone()).map_err(fast_retainer::io)?;
        let sign = request(s, "AUTO-FEE-SIGN", &prep.0);
        let out = checked(s.execute(
            sign,
            s.head(),
            Action::FeePolicySign {
                tip: Id(s.tip()),
                policy_request: self.config.policy_request,
                prepare_request: prep,
                review,
                key_file: self.config.key_file.clone(),
            },
            Some(password),
            now,
        )?)?;
        let raw = bytes(
            out["operation_hex"]
                .as_str()
                .ok_or("MISSING monitor retained signature")?,
            4096,
        )?;
        s.monitor_submit(sign, &raw, now)?;
        row["phase"] = json!("SIGNED_WAITING_NATIVE_INCLUSION");
        row["operation"] = json!(Id(fast::operation_id(&raw)));
        row["operation_included"] = json!(false);
        Ok(row)
    }
}
fn ledger_height(s: &Session) -> u128 {
    s.native.as_ref().unwrap().ledger().tip().height()
}
impl Session {
    fn monitor_proofs(&mut self, channel: Id, now: u64) -> Result<Vec<Vec<u8>>> {
        let current = self
            .native
            .as_ref()
            .unwrap()
            .ledger()
            .funding_origin(channel.0)
            .ok();
        let mut proofs = BTreeSet::new();
        for (id, state) in &self.actors {
            if state.reg.channel != channel.0 {
                continue;
            }
            if let Some(w) = self.actor_audits.get(id).filter(|w| w.head == state.head) {
                w.prefix.check(&actor_path(&self.root, *id))?;
                if let Some(current) = &current {
                    ensure(
                        current.context() == w.origin.context(),
                        "INVALID monitor backing reorganization",
                    )?;
                    for p in &w.proofs {
                        current.verify_certificate(p)?;
                    }
                }
                proofs.extend(w.proofs.iter().cloned());
                continue;
            }
            let child = Actor::open(
                &actor_path(&self.root, *id),
                self.chain,
                state.reg.role,
                state.head,
                now,
            )?;
            let (origin, _, _) = child.scope();
            let raw = match child {
                Actor::Owner(mut j) => j
                    .retained_complete(state.head)?
                    .map(|(raw, _)| {
                        Payment::verify(&origin, &raw).map(|p| vec![p.after_certificate().to_vec()])
                    })
                    .transpose()?
                    .unwrap_or_default(),
                Actor::Retainer(mut j) => j.protected_certificates(state.head)?,
            };
            if let Some(current) = &current {
                ensure(
                    current.context() == origin.context(),
                    "INVALID monitor backing reorganization",
                )?;
                for p in &raw {
                    current.verify_certificate(p)?;
                }
            }
            proofs.extend(raw);
        }
        Ok(proofs.into_iter().collect())
    }
    fn monitor_existing(
        &self,
        policy: Id,
        channel: Id,
        kind: u8,
        proof: &[u8],
        at: u64,
        now: u64,
    ) -> Result<Option<(Id, Vec<u8>)>> {
        for (index, op) in self.caller.ops.iter().enumerate().rev() {
            let Action::FeePolicySign {
                policy_request,
                prepare_request,
                review,
                ..
            } = &op.intent.action
            else {
                continue;
            };
            if *policy_request != policy {
                continue;
            }
            let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) else {
                continue;
            };
            let (_, transfer::Preparation::Escrow(mut p), _) =
                self.prepared(index, *prepare_request, *review)?
            else {
                continue;
            };
            if p.channel != channel || p.kind != kind || bytes(&p.certificate, 252)? != proof {
                continue;
            }
            p.timestamp = at.to_string();
            let ledger = self.native.as_ref().unwrap().ledger();
            let raw = bytes(raw, 4096)?;
            if ledger
                .plan_action(self.tip(), &p.request()?, now)
                .and_then(|v| v.verify_signed(&raw))
                .is_ok()
            {
                return Ok(Some((op.intent.id, raw)));
            }
        }
        Ok(None)
    }
    fn monitor_submit(&mut self, sign: Id, raw: &[u8], now: u64) -> Result<()> {
        let encoded = hex::encode(raw);
        if self.caller.ops.iter().any(|o| {
            matches!(&o.intent.action, Action::PoolSubmit{operation,..} if *operation==encoded)
                && o.done.as_ref().is_some_and(|d| d.diagnostic.is_none())
        }) {
            return Ok(());
        }
        checked(self.submit_authorized(
            self.head(),
            request(self, "AUTO-FEE-POOL", &fast::operation_id(raw)),
            sign,
            now,
        )?)?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn monitor_plan(
        &self,
        state: &fee_policy::State,
        policy: Id,
        channel: Id,
        kind: u8,
        proof: Vec<u8>,
        fee: &str,
        at: u64,
        now: u64,
    ) -> Result<OnchainRequest> {
        // Re-review exactly the same unsigned reservation after interrupted
        // preparation or a changed selected tip; never free or rebase its inputs.
        for op in self.caller.ops.iter().rev() {
            if let Action::FeePolicyPrepare {
                policy_request,
                plan,
                ..
            } = &op.intent.action
            {
                if *policy_request == policy
                    && plan.channel == channel
                    && plan.kind == kind
                    && bytes(&plan.certificate, 252)? == proof
                    && op.done.as_ref().is_some_and(|d| d.review.is_some())
                {
                    let mut p = plan.clone();
                    p.timestamp = at.to_string();
                    if state.allowed(&p).is_ok()
                        && self
                            .native
                            .as_ref()
                            .unwrap()
                            .ledger()
                            .plan_action(self.tip(), &p.request()?, now)
                            .is_ok()
                    {
                        return Ok(p);
                    }
                }
            }
        }
        let mut reserved = BTreeSet::new();
        for op in &self.caller.ops {
            if op.done.as_ref().is_some_and(|d| d.review.is_some()) {
                if let Some((_, p)) = op.intent.action.preparation() {
                    reserved.extend(p.inputs()?);
                }
            }
        }
        let ledger = self.native.as_ref().unwrap().ledger();
        let fee_value = onchain::integer(fee)?;
        let input = state
            .family
            .iter()
            .find(|i| {
                !state.used.contains(*i)
                    && !reserved.contains(*i)
                    && ledger.coins().get(*i).is_some_and(|c| {
                        c.owner == state.terms.owner.0
                            && c.amount >= fee_value
                            && c.maturity <= ledger.tip().height() + 1
                    })
            })
            .ok_or("RESOURCE_WAIT monitor unreserved mature fee input")?;
        let p = OnchainRequest {
            kind,
            channel,
            actor: state.terms.owner,
            inputs: vec![hex::encode(input)],
            fee: fee.to_string(),
            expiry: state.terms.expiry_height.clone(),
            nonce: request(
                self,
                "AUTO-FEE-NONCE",
                &[channel.0.as_slice(), &[kind], &proof].concat(),
            ),
            certificate: hex::encode(proof),
            timestamp: at.to_string(),
        };
        state.allowed(&p)?;
        ledger.plan_action(self.tip(), &p.request()?, now)?;
        Ok(p)
    }
    fn monitor_settlement(&mut self, channel: Id, now: u64) -> Result<Value> {
        let mut wanted = BTreeMap::new();
        for op in &self.caller.ops {
            if matches!(op.intent.action, Action::FeePolicySign { .. }) {
                if let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) {
                    let raw = bytes(raw, 4096)?;
                    let a = fast::planning::signed_action(&raw, self.chain)?;
                    if a.kind == 5 && a.channel == channel.0 {
                        wanted.insert(fast::operation_id(&raw), raw);
                    }
                }
            }
        }
        let n = self.native.as_mut().unwrap();
        let included = n.pool_inclusions(&wanted, now)?;
        if let Some((id, (block, height))) = included.iter().next() {
            let output = [id.as_slice(), &5u16.to_be_bytes()].concat();
            let coin = n.ledger().coins().get(&output);
            return Ok(
                json!({"channel":channel,"phase":"SETTLED","selected_tip":Id(n.ledger().tip().id()),"selected_block":Id(*block),"selected_height":height.to_string(),"operation":Id(*id),"native_inclusion_known":true,
                "miner_output_present":coin.is_some(),"miner_fee":coin.map(|c|c.amount.to_string()),"maturity_height":coin.map(|c|c.maturity.to_string()),"eligible_for_next_block":coin.map(|c|c.maturity<=n.ledger().tip().height()+1),"conditional_selected_history":true}),
            );
        }
        Ok(
            json!({"channel":channel,"phase":"BACKING_ABSENT","selected_tip":Id(n.ledger().tip().id()),"native_inclusion_known":true,"payout_known":false}),
        )
    }
}

/// Ordinary open PoW, independent of actors, fee-wallet consent or spending keys.
pub struct BackgroundMiner {
    reward: Id,
    binding: Hash,
    pool: Option<Hash>,
    last: Option<Value>,
    diagnostic: Option<String>,
}
impl BackgroundMiner {
    pub fn start(s: &mut Session, head: Hash, reward: Id, now: u64) -> Result<Self> {
        s.status(head, now)?;
        ensure(
            s.controlled() && crate::kernel::valid_point(reward.0),
            "INVALID background mining caller/reward",
        )?;
        Ok(Self {
            reward,
            binding: s.caller.binding(),
            pool: None,
            last: None,
            diagnostic: None,
        })
    }
    pub fn tick(&mut self, s: &mut Session, now: u64) -> Result<()> {
        let result = self.step(s, now);
        match &result {
            Ok(v) => {
                self.last = Some(v.clone());
                self.diagnostic = None;
            }
            Err(e) => self.diagnostic = Some(e.clone()),
        }
        result.map(|_| ())
    }
    fn step(&mut self, s: &mut Session, now: u64) -> Result<Value> {
        s.status(s.head(), now)?;
        ensure(
            s.controlled() && s.caller.binding() == self.binding,
            "INVALID background mining caller binding",
        )?;
        let pool = s.pool_binding()?;
        let v = s.mine_pool(
            s.head(),
            PoolMiningRequest {
                miner: self.reward,
                timestamp: timestamp(s, now)?.to_string(),
                attempts: 4096,
                scan_limit: 128,
                refresh: self.pool != Some(pool),
            },
            now,
        )?;
        self.pool = Some(pool);
        if v["candidate"].is_null() {
            return Ok(v);
        }
        let raw = s.candidate.as_ref().ok_or("MISSING background candidate")?;
        let id = fast::block_id(raw)?;
        let admitted = checked(s.admit_candidate(
            s.head(),
            request(s, "AUTO-MINED-BLOCK", &id),
            Id(id),
            now,
        )?)?;
        Ok(
            json!({"state":"NATIVE_ADMITTED","block":Id(id),"selected_tip":Id(s.tip()),"admission":admitted}),
        )
    }
    pub fn status(&self) -> Value {
        json!({"active":true,"reward":self.reward,"last_observation":self.last,"diagnostic":self.diagnostic,"spending_key_required":false,"fee_policy_required":false,"automatic_carriage":false,"fast_completion_authorized":false})
    }
}
