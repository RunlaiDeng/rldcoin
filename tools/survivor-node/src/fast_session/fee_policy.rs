//! Explicit fee-input-owner consent, not principal or retainer authority.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::{BTreeMap, BTreeSet};
const TERMS_LIMIT: usize = 1536;
const CERT_LIMIT: usize = 80 + TERMS_LIMIT;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicy {
    pub chain: Id,
    pub caller: Id,
    pub owner: Id,
    pub channels: Vec<Id>,
    pub inputs: Vec<String>,
    pub max_fee: String,
    pub total_fee: String,
    pub max_operations: u16,
    pub expiry_height: String,
    pub expiry_time: String,
    pub nonce: Id,
}
impl FeePolicy {
    /// Verify canonical consent bytes and supplied local scope only. This does
    /// not establish native funding, current spendability or independent freshness.
    pub fn verify_certificate(raw: &[u8], chain: Hash, caller: Hash) -> Result<Self> {
        let p = Self::verify(raw)?;
        p.scope(caller, chain)?;
        Ok(p)
    }
    pub(super) fn shape(&self) -> Result<()> {
        ensure(
            crate::kernel::valid_point(self.owner.0)
                && self.nonce.0 != [0; 32]
                && (1..=8).contains(&self.channels.len())
                && self.channels.windows(2).all(|w| w[0] < w[1])
                && (1..=8).contains(&self.inputs.len())
                && self.inputs.windows(2).all(|w| w[0] < w[1])
                && (1..=64).contains(&self.max_operations),
            "INVALID fee policy scope/counts",
        )?;
        for i in &self.inputs {
            ensure(bytes(i, 34)?.len() == 34, "INVALID fee policy input")?;
        }
        let max = onchain::integer(&self.max_fee)?;
        let total = onchain::integer(&self.total_fee)?;
        ensure(
            max > 0 && max <= total && total <= crate::kernel::CAP,
            "INVALID fee policy fee limits",
        )?;
        ensure(
            onchain::integer(&self.expiry_height)? > 0
                && onchain::integer(&self.expiry_time)? <= u64::MAX as u128,
            "INVALID fee policy expiry",
        )?;
        ensure(
            serde_json::to_vec(self).map_err(fast_retainer::io)?.len() <= TERMS_LIMIT,
            "RESOURCE_WAIT fee policy terms",
        )
    }
    fn scope(&self, caller: Hash, chain: Hash) -> Result<()> {
        self.shape()?;
        ensure(
            self.caller.0 == caller && self.chain.0 == chain,
            "INVALID fee policy caller/currency binding",
        )
    }
    pub(super) fn time(&self, height: u128, at: u64) -> Result<()> {
        ensure(
            height
                .checked_add(1)
                .is_some_and(|h| h <= onchain::integer(&self.expiry_height).unwrap_or(0))
                && (at as u128) <= onchain::integer(&self.expiry_time)?,
            "EXPIRED fee policy signing scope",
        )
    }
    fn initial(&self, ledger: &fast::Ledger, at: u64) -> Result<()> {
        self.time(ledger.tip().height(), at)?;
        let expiry = onchain::integer(&self.expiry_time)?;
        ensure(
            expiry > (at as u128) && expiry - (at as u128) <= 2678400,
            "INVALID fee policy consent horizon",
        )?;
        for channel in &self.channels {
            ledger.funding_origin(channel.0)?;
        }
        let mut total = 0u128;
        for input in &self.inputs {
            let raw = bytes(input, 34)?;
            let c = ledger
                .coins()
                .get(&raw)
                .ok_or("MISSING fee policy funding input")?;
            ensure(
                c.owner == self.owner.0 && c.maturity <= ledger.tip().height() + 1,
                "INVALID fee policy owner/maturity",
            )?;
            total = total
                .checked_add(c.amount)
                .ok_or("INVALID fee policy input sum")?;
        }
        ensure(
            onchain::integer(&self.total_fee)? <= total,
            "INVALID fee policy unfunded budget",
        )
    }
    fn frame(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let terms = serde_json::to_vec(self).map_err(fast_retainer::io)?;
        let mut raw = b"RLDFPOL1".to_vec();
        raw.extend([0, 1, 0, 1]);
        raw.extend((terms.len() as u32).to_be_bytes());
        raw.extend(terms);
        Ok(raw)
    }
    fn sign(&self, key: &SigningKey) -> Result<Vec<u8>> {
        ensure(
            key.verifying_key().to_bytes() == self.owner.0,
            "INVALID fee policy consent key",
        )?;
        let mut raw = self.frame()?;
        let message = [b"RLD-FAST-FEE-POLICY-1/CONSENT\0".as_slice(), &raw].concat();
        raw.extend(key.sign(&message).to_bytes());
        Ok(raw)
    }
    fn verify(raw: &[u8]) -> Result<Self> {
        ensure(
            (80..=CERT_LIMIT).contains(&raw.len()),
            "INVALID fee policy certificate size",
        )?;
        let mut r = fast_retainer::Reader { raw, at: 0 };
        ensure(
            r.take(8)? == b"RLDFPOL1" && r.take(4)? == [0, 1, 0, 1],
            "UNSUPPORTED fee policy certificate",
        )?;
        let n = r.u32()? as usize;
        ensure(
            n <= TERMS_LIMIT,
            "RESOURCE_WAIT fee policy certificate terms",
        )?;
        let p: Self = serde_json::from_slice(r.take(n)?)
            .map_err(|_| "INVALID fee policy certificate terms")?;
        let sig = r.take(64)?;
        ensure(
            r.at == raw.len() && p.frame()? == raw[..raw.len() - 64],
            "INVALID fee policy canonical certificate",
        )?;
        crate::kernel::verify(
            p.owner.0,
            &[
                b"RLD-FAST-FEE-POLICY-1/CONSENT\0".as_slice(),
                &raw[..raw.len() - 64],
            ]
            .concat(),
            sig,
        )?;
        Ok(p)
    }
}
pub(super) struct State {
    pub(super) terms: FeePolicy,
    pub(super) family: BTreeSet<Vec<u8>>,
    pub(super) used: BTreeSet<Vec<u8>>,
    fees: u128,
    operations: u16,
    signed: BTreeMap<Hash, Vec<u8>>,
}
impl State {
    fn new(terms: FeePolicy) -> Result<Self> {
        let family = terms
            .inputs
            .iter()
            .map(|s| bytes(s, 34))
            .collect::<Result<_>>()?;
        Ok(Self {
            terms,
            family,
            used: BTreeSet::new(),
            fees: 0,
            operations: 0,
            signed: BTreeMap::new(),
        })
    }
    pub(super) fn allowed(&self, p: &OnchainRequest) -> Result<()> {
        let p = p.request()?;
        ensure(
            (3..=5).contains(&p.kind)
                && p.actor == self.terms.owner.0
                && self.terms.channels.contains(&Id(p.channel))
                && p.fee <= onchain::integer(&self.terms.max_fee)?
                && p.expiry <= onchain::integer(&self.terms.expiry_height)?
                && (p.timestamp as u128) <= onchain::integer(&self.terms.expiry_time)?,
            "INVALID fee policy operation scope",
        )?;
        ensure(
            self.operations < self.terms.max_operations
                && self
                    .fees
                    .checked_add(p.fee)
                    .is_some_and(|f| f <= onchain::integer(&self.terms.total_fee).unwrap_or(0)),
            "RESOURCE_WAIT fee policy allowance exhausted",
        )?;
        ensure(
            p.inputs
                .iter()
                .all(|i| self.family.contains(i) && !self.used.contains(i)),
            "CONFLICT fee policy input lineage/use",
        )
    }
    fn consume(&mut self, p: &OnchainRequest, raw: &[u8], chain: Hash) -> Result<()> {
        let id = fast::operation_id(raw);
        if let Some(old) = self.signed.get(&id) {
            ensure(
                old == raw,
                "INVALID fee policy signature identity collision",
            )?;
            return Ok(());
        }
        self.allowed(p)?;
        let a = fast::planning::signed_action(raw, chain)?;
        let q = p.request()?;
        ensure(
            a.kind == q.kind
                && a.channel == q.channel
                && a.actor == q.actor
                && a.nonce == q.nonce
                && a.fee == q.fee
                && a.expiry == q.expiry
                && a.inputs == q.inputs
                && a.certificate == q.certificate,
            "INVALID fee policy changed signed plan",
        )?;
        self.fees = self
            .fees
            .checked_add(a.fee)
            .ok_or("INVALID fee policy fee sum")?;
        self.operations += 1;
        self.used.extend(a.inputs);
        if a.change > 0 {
            let mut output = id.to_vec();
            output.extend(0u16.to_be_bytes());
            self.family.insert(output);
        }
        self.signed.insert(id, raw.to_vec());
        Ok(())
    }
}
impl Session {
    pub fn fee_policy_status(&mut self, head: Hash, request: Id, now: u64) -> Result<Value> {
        self.status(head, now)?;
        let state = self.policy_state(self.caller.ops.len(), request)?;
        Ok(
            json!({"policy_request":request,"fee_wallet":state.terms.owner,"signed_fee_liability":state.fees.to_string(),
            "expiry_height":state.terms.expiry_height,"expiry_time":state.terms.expiry_time,
            "policy_time_eligible":state.terms.time(self.native.as_ref().unwrap().ledger().tip().height(),now).is_ok(),
            "signed_operations":state.operations,"remaining_fee_allowance":(onchain::integer(&state.terms.total_fee)?-state.fees).to_string(),
            "remaining_operations":state.terms.max_operations-state.operations,"current_spendability_known":false,
            "native_inclusion_known":false,"independent_freshness":false,"automatic_monitoring":false}),
        )
    }
    pub(super) fn policy(&self, before: usize, request: Id) -> Result<(usize, FeePolicy)> {
        ensure(
            self.caller.controlled(),
            "UNSUPPORTED fee policy requires controlled caller",
        )?;
        let index = self.caller.ops[..before]
            .iter()
            .position(|o| o.intent.id == request)
            .ok_or("MISSING retained fee policy consent")?;
        let op = &self.caller.ops[index];
        let Action::FeePolicyApprove {
            terms, approved, ..
        } = &op.intent.action
        else {
            return Err("INVALID fee policy consent type".into());
        };
        ensure(*approved, "INVALID fee policy explicit consent")?;
        let raw = op
            .done
            .as_ref()
            .and_then(|d| d.authorization.as_ref())
            .ok_or("MISSING signed fee policy consent")?;
        let p = FeePolicy::verify(&bytes(raw, CERT_LIMIT)?)?;
        ensure(
            p.frame()? == terms.frame()?,
            "INVALID fee policy changed terms",
        )?;
        p.scope(self.caller.binding(), self.chain)?;
        Ok((index, p))
    }
    fn policy_preparation(
        &self,
        before: usize,
        policy: Id,
        prepare: Id,
        review: Id,
    ) -> Result<(OnchainRequest, Hash)> {
        let (index, p, tip) = self.prepared(before, prepare, review)?;
        ensure(
            matches!(&self.caller.ops[index].intent.action,Action::FeePolicyPrepare{policy_request,..} if *policy_request==policy),
            "INVALID policy signing preparation binding",
        )?;
        let transfer::Preparation::Escrow(plan) = p else {
            return Err("INVALID fee policy preparation kind".into());
        };
        Ok((plan, tip))
    }
    pub(super) fn policy_state(&self, before: usize, request: Id) -> Result<State> {
        let (start, p) = self.policy(before, request)?;
        let mut state = State::new(p)?;
        for (index, op) in self.caller.ops[..before].iter().enumerate().skip(start + 1) {
            if let Action::FeePolicySign {
                policy_request,
                prepare_request,
                review,
                ..
            } = &op.intent.action
            {
                if *policy_request == request {
                    if let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) {
                        let (p, _) =
                            self.policy_preparation(index, request, *prepare_request, *review)?;
                        state.consume(&p, &bytes(raw, 4096)?, self.chain)?;
                    }
                }
            }
        }
        Ok(state)
    }
    pub(super) fn policy_families(&self, before: usize) -> Result<Vec<(Id, State)>> {
        let mut result = vec![];
        for op in &self.caller.ops[..before] {
            if matches!(op.intent.action, Action::FeePolicyApprove { .. })
                && op.done.as_ref().is_some_and(|d| d.authorization.is_some())
            {
                ensure(result.len() < 8, "RESOURCE_WAIT fee policy count")?;
                result.push((op.intent.id, self.policy_state(before, op.intent.id)?));
            }
        }
        Ok(result)
    }
    fn fee_preflight_at(&self, action: &Action, before: usize) -> Result<()> {
        let policies = self.policy_families(before)?;
        if let Action::FeePolicyApprove { terms, .. } = action {
            ensure(
                self.caller.controlled() && policies.len() < 8,
                "RESOURCE_WAIT fee policy controlled count",
            )?;
            terms.scope(self.caller.binding(), self.chain)?;
            let roots = terms
                .inputs
                .iter()
                .map(|s| bytes(s, 34))
                .collect::<Result<Vec<_>>>()?;
            ensure(
                policies
                    .iter()
                    .all(|(_, p)| roots.iter().all(|r| !p.family.contains(r))),
                "CONFLICT fee policy overlapping funding",
            )?;
            for op in &self.caller.ops[..before] {
                if let Some((_, p)) = op.intent.action.preparation() {
                    if op.done.as_ref().is_some_and(|d| d.review.is_some()) {
                        ensure(
                            p.inputs()?.iter().all(|i| !roots.contains(i)),
                            "CONFLICT fee policy prepared funding",
                        )?;
                    }
                }
            }
        }
        if let Some((_, p)) = action.preparation() {
            let inputs = p.inputs()?;
            for (id, state) in &policies {
                if matches!(action,Action::FeePolicyPrepare{policy_request,..} if policy_request==id)
                {
                    continue;
                }
                ensure(
                    inputs.iter().all(|i| !state.family.contains(i)),
                    "CONFLICT input reserved by fee policy",
                )?;
            }
            if let Action::FeePolicyPrepare {
                policy_request,
                plan,
                ..
            } = action
            {
                self.policy_state(before, *policy_request)?.allowed(plan)?;
            }
        }
        if let Action::OnchainSign {
            prepare_request, ..
        } = action
        {
            if let Some(op) = self.caller.ops[..before]
                .iter()
                .find(|o| o.intent.id == *prepare_request)
            {
                ensure(
                    !matches!(op.intent.action, Action::FeePolicyPrepare { .. }),
                    "INVALID policy preparation requires policy signing",
                )?;
            }
        }
        Ok(())
    }
    pub(super) fn fee_preflight(&self, a: &Action) -> Result<()> {
        self.fee_preflight_at(a, self.caller.ops.len())
    }
    pub(super) fn fee_prepare_time(&mut self, request: Id, tip: Hash, now: u64) -> Result<()> {
        let (_, p) = self.policy(self.caller.ops.len() - 1, request)?;
        let n = self.native.as_mut().unwrap();
        let current = n.current(n.head(), tip, now)?;
        p.time(current.ledger.tip().height(), now)
    }
    pub(super) fn fee_apply(
        &mut self,
        a: &Action,
        password: Option<&[u8]>,
        now: u64,
    ) -> Result<Option<String>> {
        let before = self.caller.ops.len() - 1;
        match a {
            Action::FeePolicyApprove {
                tip,
                terms,
                key_file,
                approved,
            } => {
                ensure(*approved, "INVALID fee policy explicit consent required")?;
                terms.scope(self.caller.binding(), self.chain)?;
                let n = self.native.as_mut().unwrap();
                let current = n.current(n.head(), tip.0, now)?;
                terms.initial(current.ledger, now)?;
                let key = load_key(Path::new(key_file), self.chain, password)?;
                Ok(Some(hex::encode(terms.sign(&key)?)))
            }
            Action::FeePolicySign {
                tip,
                policy_request,
                prepare_request,
                review,
                key_file,
            } => {
                let (plan, original) =
                    self.policy_preparation(before, *policy_request, *prepare_request, *review)?;
                ensure(original == tip.0, "INVALID fee policy changed review tip")?;
                let mut state = self.policy_state(before, *policy_request)?;
                let n = self.native.as_mut().unwrap();
                let current = n.current(n.head(), tip.0, now)?;
                let native = current.ledger.plan_action(tip.0, &plan.request()?, now)?;
                ensure(
                    native.review() == review.0,
                    "INVALID fee policy stale native review",
                )?;
                for op in &self.caller.ops[..before] {
                    if matches!(&op.intent.action,Action::FeePolicySign{policy_request:p,prepare_request:q,..} if p==policy_request && q==prepare_request)
                    {
                        if let Some(raw) = op.done.as_ref().and_then(|d| d.authorization.as_ref()) {
                            native.verify_signed(&bytes(raw, 4096)?)?;
                            return Ok(Some(raw.clone()));
                        }
                    }
                }
                state.terms.time(current.ledger.tip().height(), now)?;
                state.allowed(&plan)?;
                let key = load_key(Path::new(key_file), self.chain, password)?;
                let raw = native.sign(&key)?;
                state.consume(&plan, &raw, self.chain)?;
                Ok(Some(hex::encode(raw)))
            }
            _ => Err("INVALID fee policy signing method".into()),
        }
    }
    pub(super) fn audit_fee_step(
        &mut self,
        index: usize,
        context: Hash,
        historical: &mut onchain::HistoricalAudit,
    ) -> Result<bool> {
        let op = self.caller.ops[index].clone();
        let Some(done) = op.done else {
            return Ok(false);
        };
        if op.intent.action.preparation().is_some()
            || matches!(op.intent.action, Action::OnchainSign { .. })
        {
            self.fee_preflight_at(&op.intent.action, index)?;
        }
        match &op.intent.action {
            Action::FeePolicyApprove {
                tip,
                terms,
                approved,
                ..
            } => {
                ensure(
                    done.effect.is_none() && done.review.is_none(),
                    "INVALID fee policy consent effect",
                )?;
                if let Some(raw) = &done.authorization {
                    self.fee_preflight_at(&op.intent.action, index)?;
                    ensure(
                        *approved && tip.0 == context,
                        "INVALID fee policy consent selection",
                    )?;
                    let p = FeePolicy::verify(&bytes(raw, CERT_LIMIT)?)?;
                    ensure(
                        p.frame()? == terms.frame()?,
                        "INVALID changed fee policy consent",
                    )?;
                    p.scope(self.caller.binding(), self.chain)?;
                    let native = self.audit_ledger(historical, context)?;
                    p.initial(native, op.intent.at)?;
                }
                Ok(true)
            }
            Action::FeePolicySign {
                tip,
                policy_request,
                prepare_request,
                review,
                ..
            } => {
                ensure(
                    done.effect.is_none() && done.review.is_none(),
                    "INVALID fee policy signature effect",
                )?;
                if let Some(raw) = &done.authorization {
                    ensure(tip.0 == context, "INVALID fee policy signature selection")?;
                    let (plan, original) =
                        self.policy_preparation(index, *policy_request, *prepare_request, *review)?;
                    ensure(original == tip.0, "INVALID fee policy original selection")?;
                    let mut state = self.policy_state(index, *policy_request)?;
                    let ledger = self.audit_ledger(historical, context)?;
                    let native = ledger.plan_action(context, &plan.request()?, op.intent.at)?;
                    ensure(
                        native.review() == review.0,
                        "INVALID fee policy signature review",
                    )?;
                    let raw = bytes(raw, 4096)?;
                    native.verify_signed(&raw)?;
                    if !state.signed.contains_key(&fast::operation_id(&raw)) {
                        state.terms.time(ledger.tip().height(), op.intent.at)?;
                    }
                    state.consume(&plan, &raw, self.chain)?;
                }
                Ok(true)
            }
            // The generic preparation audit reconstructs the complete native
            // ledger and checks both policy time and value against that ledger.
            Action::FeePolicyPrepare { .. } => Ok(false),
            _ => Ok(false),
        }
    }
    pub(super) fn policy_output(&self, a: &Action, done: &Done) -> Result<Option<Value>> {
        if matches!(a, Action::FeePolicyApprove { .. }) {
            if let Some(raw) = &done.authorization {
                let raw = bytes(raw, CERT_LIMIT)?;
                let p = FeePolicy::verify(&raw)?;
                return Ok(Some(
                    json!({"policy":Id(hash("FEE-POLICY-CERT",&raw)),"policy_hex":hex::encode(raw),"fee_wallet":p.owner,
                    "max_operation_fee":p.max_fee,"total_signature_fee_budget":p.total_fee,"automatic_monitoring":false,"principal_authority":false}),
                ));
            }
        }
        Ok(None)
    }
}
