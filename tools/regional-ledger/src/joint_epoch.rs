//! Separately admitted, controller-carried joint epoch ground candidate.
//! Old BFT first certifies one plan in a normal block. Only that exact plan can
//! seal the old journal and gather 3-of-4 old/new activation approvals.
use super::*;

pub const ACTIVATION: &str = "RLD-BFT-JOINT-EPOCH-V1";
pub const ROLE_ACTIVATION: &str = "RLD-BFT-JOINT-ROLES-V1";
pub fn activation(rules: &str) -> Result<&'static str> {
    match rules {
        bft::JOINT_RULES => Ok(ACTIVATION),
        bft::ROLE_RULES => Ok(ROLE_ACTIVATION),
        _ => Err("joint activation requires explicit signed admission".into()),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub currency: Hash,
    pub region: Hash,
    pub previous_epoch: Hash,
    pub number: u64,
    pub validators: Vec<String>,
}
impl Plan {
    pub fn validate(&self, trust: &Trust, registry: &epoch::Registry) -> Result<()> {
        let (previous, number, keys, _) = registry.latest(trust, self.region)?;
        require(
            crate::bft::is_joint(&trust.region(self.region)?.rules)
                && self.currency == trust.currency()?
                && self.previous_epoch == previous
                && self.number == number + 1
                && self.number <= epoch::MAX_EPOCHS as u64
                && self.validators.len() == 4
                && self.validators.windows(2).all(|k| k[0] < k[1])
                && self.validators != keys
                && (trust.region(self.region)?.rules == bft::ROLE_RULES
                    || self.validators.iter().all(|k| !keys.contains(k))),
            "joint plan requires the current epoch and four ordered admitted successor keys",
        )?;
        for key in &self.validators {
            validate_ed25519_public_key(key)?;
        }
        registry.fresh_bft_keys(trust, self.region, &self.validators)
    }
    pub fn matches(&self, s: &epoch::EpochStatement) -> bool {
        self.currency == s.currency
            && self.region == s.region
            && self.previous_epoch == s.previous_epoch
            && self.number == s.number
            && self.validators == s.validators
            && matches!(s.activation.as_deref(), Some(ACTIVATION | ROLE_ACTIVATION))
    }
}

pub(crate) fn selected(block: &Block) -> Result<Option<&Plan>> {
    let mut result = None;
    for command in &block.commands {
        if let Command::Reconfigure(plan) = command {
            require(result.is_none(), "at most one joint plan per block")?;
            result = Some(plan.as_ref());
        }
    }
    Ok(result)
}

/// Execution uses only the verified epoch prefix active at this exact height;
/// later carried epochs cannot retroactively select a different old key set.
pub(crate) fn validate_command(
    plan: &Plan,
    region: Hash,
    height: u64,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<()> {
    require(plan.region == region, "joint plan wrong execution region")?;
    let proofs = evidence.epoch_proofs(region);
    let active: Vec<_> = proofs
        .into_iter()
        .take_while(|p| p.statement.closing_height < height)
        .collect();
    let registry = epoch::Registry::verify_chain(trust, region, &active)?;
    plan.validate(trust, &registry)
}

pub(crate) fn selection_matches(proof: &epoch::Transition, snapshot: &Snapshot) -> Result<()> {
    require(
        proof.selection.as_deref() == snapshot.blocks.last(),
        "joint activation selection differs from fully replayed closing block",
    )
}

/// A different fully verified prepare/commit quorum can certify the same
/// closing statement. Its complete native body and headers must still match.
pub(crate) fn closing_matches(proof: &epoch::Transition, snapshot: &Snapshot) -> Result<()> {
    selection_matches(proof, snapshot)?;
    require(
        proof.closing.statement == snapshot.statement
            && proof.closing.headers
                == snapshot
                    .blocks
                    .iter()
                    .map(|b| b.header.clone())
                    .collect::<Vec<_>>(),
        "joint closing differs from complete native replay",
    )
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Old,
    New,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CarriedApproval {
    pub format: String,
    pub proposal: Box<epoch::Transition>,
    pub previous_epochs: Vec<epoch::Transition>,
    pub role: Role,
    pub approval: Approval,
}
impl CarriedApproval {
    pub fn verify(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        self.verify_scope(trust, evidence)?;
        verify_bytes(
            &self.approval.key,
            &self.proposal.statement.approval_bytes(self.role)?,
            &self.approval.signature,
        )
    }
    pub(crate) fn verify_scope(&self, trust: &Trust, evidence: &VerifiedEvidence) -> Result<()> {
        let s = &self.proposal.statement;
        let format = if trust.region(s.region)?.rules == bft::ROLE_RULES {
            "RLD-JOINT-EPOCH-APPROVAL-V2"
        } else {
            "RLD-JOINT-EPOCH-APPROVAL-V1"
        };
        require(
            self.format == format
                && crate::bft::is_joint(&trust.region(s.region)?.rules)
                && self.proposal.old_approvals.is_empty()
                && self.proposal.new_approvals.is_empty()
                && self.previous_epochs.len() + 1 == s.number as usize,
            "carried joint approval format/profile/unsigned proposal",
        )?;
        require(
            evidence
                .epoch_proofs(s.region)
                .iter()
                .take(self.previous_epochs.len())
                .map(|p| p.statement.id())
                .collect::<Result<Vec<_>>>()?
                == self
                    .previous_epochs
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?,
            "carried joint approval differs from native prior epochs",
        )?;
        let mut checked = evidence.clone();
        for prior in &self.previous_epochs {
            checked.install_epoch(prior.clone(), trust)?;
        }
        let registry = epoch::Registry::verify_chain(trust, s.region, &self.previous_epochs)?;
        let (previous, number, keys, floor) = registry.latest(trust, s.region)?;
        self.proposal
            .validate_request(trust, previous, number, &keys, floor)?;
        registry.fresh_bft_keys(trust, s.region, &s.validators)?;
        closing_matches(&self.proposal, evidence.snapshot(s.closing_checkpoint)?)?;
        let members = match self.role {
            Role::Old => &keys,
            Role::New => &s.validators,
        };
        require(
            members.contains(&self.approval.key),
            "carried joint approval wrong old/new role",
        )?;
        Ok(())
    }
}

pub fn unsigned(
    evidence: &VerifiedEvidence,
    trust: &Trust,
    sid: Hash,
) -> Result<(epoch::Transition, Vec<epoch::Transition>)> {
    let snapshot = evidence.snapshot(sid)?;
    let block = snapshot.blocks.last().ok_or("joint closing block absent")?;
    let plan = selected(block)?.ok_or("native closing has no joint plan")?;
    let previous_epochs = evidence
        .epoch_proofs(plan.region)
        .into_iter()
        .take_while(|p| p.statement.closing_height < snapshot.statement.height)
        .collect::<Vec<_>>();
    let registry = epoch::Registry::verify_chain(trust, plan.region, &previous_epochs)?;
    plan.validate(trust, &registry)?;
    let proof = epoch::Transition {
        selection: Some(Box::new(block.clone())),
        statement: epoch::EpochStatement {
            activation: Some(activation(&trust.region(plan.region)?.rules)?.into()),
            currency: plan.currency,
            region: plan.region,
            number: plan.number,
            previous_epoch: plan.previous_epoch,
            closing_checkpoint: sid,
            closing_height: snapshot.statement.height,
            validators: plan.validators.clone(),
        },
        closing: epoch::Anchor::from_snapshot(snapshot),
        old_approvals: vec![],
        new_approvals: vec![],
    };
    let (previous, number, keys, floor) = registry.latest(trust, plan.region)?;
    proof.validate_request(trust, previous, number, &keys, floor)?;
    Ok((proof, previous_epochs))
}

pub fn combine(
    votes: &[CarriedApproval],
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<epoch::Transition> {
    require(
        !votes.is_empty() && votes.len() <= 8,
        "joint approval collection bound",
    )?;
    let first = &votes[0];
    let mut old = BTreeMap::new();
    let mut new = BTreeMap::new();
    for vote in votes {
        vote.verify(trust, evidence)?; // Every complete body is authenticated before deduplication.
        require(
            vote.proposal.statement == first.proposal.statement
                && vote.proposal.selection == first.proposal.selection
                && vote
                    .previous_epochs
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?
                    == first
                        .previous_epochs
                        .iter()
                        .map(|p| p.statement.id())
                        .collect::<Result<Vec<_>>>()?,
            "joint collection mixes selection or epoch authority",
        )?;
        let collection = match vote.role {
            Role::Old => &mut old,
            Role::New => &mut new,
        };
        if let Some(prior) = collection.insert(vote.approval.key.clone(), vote.approval.clone()) {
            require(
                prior == vote.approval,
                "joint duplicate signer changed approval",
            )?;
        }
    }
    let mut proof = (*first.proposal).clone();
    proof.old_approvals = old.into_values().collect();
    proof.new_approvals = new.into_values().collect();
    let mut verified = evidence.clone();
    verified.install_epoch(proof.clone(), trust)?;
    Ok(proof)
}

/// A certified plan stops old-era successors, including timeout signing.
/// Only a complete, already native-verified exact activation permits progress.
pub(crate) fn next_epoch(
    chain: &Chain,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<Hash> {
    if !crate::bft::is_joint(&trust.region(chain.region)?.rules) {
        return Ok(chain.epoch);
    }
    let Some(block) = chain.blocks.last() else {
        return Ok(chain.epoch);
    };
    let Some(plan) = selected(block)? else {
        return Ok(chain.epoch);
    };
    let proof = evidence
        .epochs
        .regions
        .get(&chain.region)
        .and_then(|list| {
            list.iter().find(|p| {
                plan.matches(&p.statement)
                    && p.statement.closing_height == chain.height()
                    && p.selection.as_deref() == Some(block)
            })
        })
        .ok_or("certified joint plan pauses old consensus until complete activation")?;
    let snapshot = evidence.snapshot(proof.statement.closing_checkpoint)?;
    require(
        snapshot.blocks == chain.blocks
            && snapshot.statement.state == chain.ledger.root()?
            && snapshot.statement.block == chain.tip()?
            && proof.closing.statement == snapshot.statement
            && proof.closing.headers
                == snapshot
                    .blocks
                    .iter()
                    .map(|b| b.header.clone())
                    .collect::<Vec<_>>(),
        "joint activation lacks exact native-replayed closing state",
    )?;
    let next = proof.statement.id()?;
    require(
        chain.epoch == plan.previous_epoch || chain.epoch == next,
        "joint successor has unrelated epoch",
    )?;
    Ok(next)
}

pub(crate) fn signing_context(
    c: &bft::Context,
    trust: &Trust,
    evidence: &VerifiedEvidence,
) -> Result<()> {
    if !crate::bft::is_joint(&trust.region(c.region)?.rules) {
        return Ok(());
    }
    if let Some(previous) = c.previous {
        let parent = evidence.snapshot(previous)?;
        if let Some(plan) = parent.blocks.last().map(selected).transpose()?.flatten() {
            require(
                parent.statement.height == c.parent_height
                    && parent.statement.block == c.parent_block
                    && parent.statement.state == c.parent_state
                    && plan.previous_epoch != c.epoch,
                "selected joint plan forbids every old-era successor signature",
            )?;
        }
    }
    Ok(())
}

pub(crate) fn approvals(votes: &[Approval], keys: &[String], bytes: &[u8]) -> Result<()> {
    require(
        keys.len() == 4
            && keys.windows(2).all(|k| k[0] < k[1])
            && (3..=4).contains(&votes.len())
            && votes.windows(2).all(|v| v[0].key < v[1].key),
        "joint activation requires three distinct ordered old and new approvals",
    )?;
    for vote in votes {
        require(
            keys.contains(&vote.key),
            "joint activation wrong signer role",
        )?;
        verify_bytes(&vote.key, bytes, &vote.signature)?;
    }
    Ok(())
}
