//! Unanimous validator handoff with a signed closing checkpoint. This is not
//! a BFT view-change protocol and has no missing-signer liveness guarantee.
use super::*;
pub const MAX_EPOCHS: usize = 16;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bft: Option<crate::bft::Certificate>,
    pub statement: Statement,
    pub approvals: Vec<Approval>,
    pub headers: Vec<Header>,
}
impl Anchor {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        Self {
            bft: snapshot.bft.clone(),
            statement: snapshot.statement.clone(),
            approvals: snapshot.approvals.clone(),
            headers: snapshot.blocks.iter().map(|b| b.header.clone()).collect(),
        }
    }
    pub fn verify(&self, trust: &Trust, keys: &[String]) -> Result<()> {
        let s = &self.statement;
        trust.region(s.region)?;
        if crate::segmented::is_profile(&trust.region(s.region)?.rules) {
            require(s.currency == trust.currency()?, "segmented anchor currency")?;
            crate::bft::checkpoint_auth(
                s,
                &self.approvals,
                self.bft.as_ref(),
                &self.headers,
                keys,
                trust,
            )?;
            return crate::segmented::headers(s, &self.headers, trust);
        }
        require(
            s.currency == trust.currency()?
                && s.height > 0
                && self.headers.len() as u64 == s.height
                && self.headers.len() <= MAX_BLOCKS,
            "invalid epoch anchor identity or bound",
        )?;
        crate::bft::checkpoint_auth(
            s,
            &self.approvals,
            self.bft.as_ref(),
            &self.headers,
            keys,
            trust,
        )?;
        let mut parent = s.region;
        for (i, h) in self.headers.iter().enumerate() {
            require(
                h.currency == s.currency
                    && h.region == s.region
                    && h.height == i as u64 + 1
                    && h.parent == parent
                    && h.work_valid()?,
                "invalid signed anchor ancestry",
            )?;
            validate_ed25519_public_key(&h.miner)?;
            parent = h.id()?;
        }
        require(
            parent == s.block && self.headers.last().is_some_and(|h| h.state == s.state),
            "epoch anchor differs from authenticated terminal",
        )
    }
}
pub fn approvals(votes: &[Approval], keys: &[String], bytes: &[u8]) -> Result<()> {
    require(
        keys.len() == 4 && keys.windows(2).all(|k| k[0] < k[1]) && votes.len() == keys.len(),
        "unanimous ordered approvals required",
    )?;
    for (vote, key) in votes.iter().zip(keys) {
        require(&vote.key == key, "wrong era signer")?;
        verify_bytes(key, bytes, &vote.signature)?;
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EpochStatement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<String>,
    pub currency: Hash,
    pub region: Hash,
    pub number: u64,
    pub previous_epoch: Hash,
    pub closing_checkpoint: Hash,
    pub closing_height: u64,
    pub validators: Vec<String>,
}
impl EpochStatement {
    fn purpose(&self) -> Result<&'static str> {
        match self.activation.as_deref() {
            None => Ok("unanimous-epoch-handoff"),
            Some(crate::joint_epoch::ACTIVATION) => Ok("joint-epoch-handoff-v1"),
            Some(crate::joint_epoch::ROLE_ACTIVATION) => Ok("joint-role-epoch-handoff-v1"),
            _ => Err("unknown epoch activation domain".into()),
        }
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode(self.purpose()?, self)
    }
    pub fn approval_bytes(&self, role: crate::joint_epoch::Role) -> Result<Vec<u8>> {
        if self.activation.as_deref() == Some(crate::joint_epoch::ROLE_ACTIVATION) {
            encode("joint-epoch-role-approval-v1", &(role, self))
        } else {
            self.bytes()
        }
    }
    pub fn id(&self) -> Result<Hash> {
        id(self.purpose()?, self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<Box<Block>>,
    pub statement: EpochStatement,
    pub closing: Anchor,
    pub old_approvals: Vec<Approval>,
    pub new_approvals: Vec<Approval>,
}
impl Transition {
    pub fn validate_request(
        &self,
        trust: &Trust,
        previous: Hash,
        number: u64,
        keys: &[String],
        floor: u64,
    ) -> Result<()> {
        let s = &self.statement;
        require(
            trust.region(s.region)?.rules == DOMAIN
                || crate::bft::has_epochs(&trust.region(s.region)?.rules),
            "BFT-profile joint epoch signer activation is not implemented",
        )?;
        require(
            s.currency == trust.currency()?
                && s.region == self.closing.statement.region
                && s.number == number + 1
                && s.number <= MAX_EPOCHS as u64
                && s.previous_epoch == previous
                && s.closing_checkpoint == self.closing.statement.id()?
                && s.closing_height == self.closing.statement.height
                && s.closing_height > floor
                && self.closing.statement.epoch == previous,
            "handoff identity, number or closing fence mismatch",
        )?;
        require(
            s.validators.len() == 4
                && s.validators.windows(2).all(|k| k[0] < k[1])
                && s.validators != keys,
            "new validator set is invalid or unchanged",
        )?;
        for key in &s.validators {
            validate_ed25519_public_key(key)?;
        }
        if crate::bft::has_epochs(&trust.region(s.region)?.rules)
            && trust.region(s.region)?.rules != crate::bft::ROLE_RULES
        {
            require(
                s.validators.iter().all(|key| !keys.contains(key)),
                "BFT epoch activation requires a disjoint fresh validator set",
            )?;
        }
        if crate::bft::is_joint(&trust.region(s.region)?.rules) {
            require(
                s.activation.as_deref()
                    == Some(crate::joint_epoch::activation(
                        &trust.region(s.region)?.rules,
                    )?),
                "joint activation marker differs from signed admission",
            )?;
            let block = self
                .selection
                .as_deref()
                .ok_or("joint activation lacks certified selection block")?;
            let plan = crate::joint_epoch::selected(block)?
                .ok_or("closing block has no joint selection")?;
            require(
                plan.matches(s)
                    && self.closing.headers.last() == Some(&block.header)
                    && block.header.commands == id("commands", &block.commands)?,
                "joint activation changes the certified plan or closing body",
            )?;
        } else {
            require(
                s.activation.is_none() && self.selection.is_none(),
                "legacy activation cannot carry joint selection/domain",
            )?;
        }
        self.closing.verify(trust, keys)
    }
    pub fn verify(
        &self,
        trust: &Trust,
        previous: Hash,
        number: u64,
        keys: &[String],
        floor: u64,
    ) -> Result<()> {
        self.validate_request(trust, previous, number, keys, floor)?;
        let bytes = self.statement.bytes()?;
        if crate::bft::is_joint(&trust.region(self.statement.region)?.rules) {
            crate::joint_epoch::approvals(
                &self.old_approvals,
                keys,
                &self
                    .statement
                    .approval_bytes(crate::joint_epoch::Role::Old)?,
            )?;
            crate::joint_epoch::approvals(
                &self.new_approvals,
                &self.statement.validators,
                &self
                    .statement
                    .approval_bytes(crate::joint_epoch::Role::New)?,
            )
        } else {
            approvals(&self.old_approvals, keys, &bytes)?;
            approvals(&self.new_approvals, &self.statement.validators, &bytes)
        }
    }
}
#[derive(Clone, Default)]
pub struct Registry {
    pub(crate) regions: BTreeMap<Hash, Vec<Transition>>,
}
impl Registry {
    pub(crate) fn fresh_bft_keys(
        &self,
        trust: &Trust,
        region: Hash,
        validators: &[String],
    ) -> Result<()> {
        if crate::bft::has_epochs(&trust.region(region)?.rules) {
            let mut historical = trust.region(region)?.validators.clone();
            for old in self.proofs(region) {
                historical.extend(old.statement.validators);
            }
            let current = self.latest(trust, region)?.2;
            let roles = trust.region(region)?.rules == crate::bft::ROLE_RULES;
            require(
                validators
                    .iter()
                    .all(|key| !historical.contains(key) || (roles && current.contains(key))),
                "BFT epoch cannot reactivate a historically fenced validator key",
            )?;
        }
        Ok(())
    }

    pub fn initial(trust: &Trust, region: Hash) -> Result<Hash> {
        let admission = trust.region(region)?;
        id("initial-validator-epoch", &(region, &admission.validators))
    }
    pub fn latest(&self, trust: &Trust, region: Hash) -> Result<(Hash, u64, Vec<String>, u64)> {
        match self.regions.get(&region).and_then(|v| v.last()) {
            Some(t) => Ok((
                t.statement.id()?,
                t.statement.number,
                t.statement.validators.clone(),
                t.statement.closing_height,
            )),
            None => Ok((
                Self::initial(trust, region)?,
                0,
                trust.region(region)?.validators.clone(),
                0,
            )),
        }
    }
    pub fn proofs(&self, region: Hash) -> Vec<Transition> {
        self.regions.get(&region).cloned().unwrap_or_default()
    }
    pub fn verify_chain(trust: &Trust, region: Hash, proofs: &[Transition]) -> Result<Self> {
        require(proofs.len() <= MAX_EPOCHS, "epoch proof count bound")?;
        let mut registry = Self::default();
        for p in proofs {
            require(p.statement.region == region, "wrong-region epoch proof")?;
            registry.add_authority(p.clone(), trust)?;
        }
        Ok(registry)
    }
    pub fn add_authority(&mut self, proof: Transition, trust: &Trust) -> Result<Hash> {
        encode("epoch-proof", &proof)?;
        let eid = proof.statement.id()?;
        if let Some(existing) = self
            .regions
            .get(&proof.statement.region)
            .and_then(|list| list.iter().find(|p| p.statement.id().ok() == Some(eid)))
        {
            if existing != &proof {
                require(
                    crate::bft::is_joint(&trust.region(proof.statement.region)?.rules)
                        && existing.statement == proof.statement
                        && existing.selection == proof.selection
                        && existing.closing.statement == proof.closing.statement
                        && existing.closing.headers == proof.closing.headers,
                    "inconsistent duplicate epoch proof",
                )?;
                let earlier = self
                    .proofs(proof.statement.region)
                    .into_iter()
                    .take_while(|p| p.statement.id().ok() != Some(eid))
                    .collect::<Vec<_>>();
                let registry = Self::verify_chain(trust, proof.statement.region, &earlier)?;
                let (previous, number, keys, floor) =
                    registry.latest(trust, proof.statement.region)?;
                proof.verify(trust, previous, number, &keys, floor)?;
            }
            return Ok(eid);
        }
        let (previous, number, keys, floor) = self.latest(trust, proof.statement.region)?;
        self.fresh_bft_keys(trust, proof.statement.region, &proof.statement.validators)?;
        proof.verify(trust, previous, number, &keys, floor)?;
        let list = self.regions.entry(proof.statement.region).or_default();
        require(list.len() < MAX_EPOCHS, "epoch capacity full")?;
        list.push(proof);
        Ok(eid)
    }
    pub fn checkpoint_keys(&self, trust: &Trust, statement: &Statement) -> Result<Vec<String>> {
        let mut epoch = Self::initial(trust, statement.region)?;
        let mut keys = trust.region(statement.region)?.validators.clone();
        for proof in self.proofs(statement.region) {
            if statement.height <= proof.statement.closing_height {
                break;
            }
            epoch = proof.statement.id()?;
            keys = proof.statement.validators;
        }
        require(
            statement.epoch == epoch,
            "checkpoint uses an unknown, retired or premature epoch",
        )?;
        Ok(keys)
    }
    pub fn install(
        &mut self,
        proof: Transition,
        trust: &Trust,
        snapshots: &BTreeMap<Hash, (Snapshot, Ledger)>,
    ) -> Result<Hash> {
        let eid = proof.statement.id()?;
        let source = snapshots
            .get(&proof.statement.closing_checkpoint)
            .ok_or("handoff closing checkpoint has not been value-replayed")?;
        if crate::bft::is_joint(&trust.region(proof.statement.region)?.rules) {
            crate::joint_epoch::closing_matches(&proof, &source.0)?;
        } else {
            require(
                Anchor::from_snapshot(&source.0) == proof.closing,
                "handoff anchor differs from verified source",
            )?;
        }
        if crate::bft::is_joint(&trust.region(proof.statement.region)?.rules) {
            crate::joint_epoch::selection_matches(&proof, &source.0)?;
        }
        if !self
            .proofs(proof.statement.region)
            .iter()
            .any(|p| p.statement.id().ok() == Some(eid))
        {
            let latest = snapshots
                .values()
                .filter(|(s, _)| s.statement.region == proof.statement.region)
                .max_by_key(|(s, _)| s.statement.height)
                .ok_or("missing latest closing source")?;
            require(
                latest.0.statement.id()? == proof.statement.closing_checkpoint,
                "handoff closes behind an already accepted checkpoint",
            )?;
        }
        self.add_authority(proof, trust)
    }
}
