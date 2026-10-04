//! Authenticated incompatible checkpoint histories, not a consensus repair.
//! Histories authenticate ancestry only; a signed invalid ledger is still a
//! signer safety failure. Neither branch is installed by an incident proof.
use super::*;
pub const MAX_INCIDENTS: usize = 16;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertifiedHistory {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bft: Option<crate::bft::Certificate>,
    pub statement: Statement,
    pub approvals: Vec<Approval>,
    pub headers: Vec<Header>,
    pub epochs: Vec<epoch::Transition>,
}
impl CertifiedHistory {
    pub fn from_snapshot(snapshot: &Snapshot) -> Self {
        Self {
            bft: snapshot.bft.clone(),
            statement: snapshot.statement.clone(),
            approvals: snapshot.approvals.clone(),
            headers: snapshot.blocks.iter().map(|b| b.header.clone()).collect(),
            epochs: snapshot.epochs.clone(),
        }
    }
    pub fn context_id(&self) -> Result<Hash> {
        id(
            "certified-history-context",
            &(
                self.statement.id()?,
                self.epochs
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?,
            ),
        )
    }
    pub fn verify(&self, trust: &Trust) -> Result<()> {
        require(
            !crate::segmented::is_profile(&trust.region(self.statement.region)?.rules)
                || self.epochs.is_empty(),
            "segmented incident cannot invent an epoch handoff",
        )?;
        let registry = epoch::Registry::verify_chain(trust, self.statement.region, &self.epochs)?;
        let keys = registry.checkpoint_keys(trust, &self.statement)?;
        epoch::Anchor {
            bft: self.bft.clone(),
            statement: self.statement.clone(),
            approvals: self.approvals.clone(),
            headers: self.headers.clone(),
        }
        .verify(trust, &keys)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub left: CertifiedHistory,
    pub right: CertifiedHistory,
}
impl Conflict {
    pub fn canonical(left: CertifiedHistory, right: CertifiedHistory) -> Result<Self> {
        let (left, right) = if left.context_id()? < right.context_id()? {
            (left, right)
        } else {
            (right, left)
        };
        Ok(Self { left, right })
    }
    pub fn from_snapshots(left: &Snapshot, right: &Snapshot) -> Result<Self> {
        Self::canonical(
            CertifiedHistory::from_snapshot(left),
            CertifiedHistory::from_snapshot(right),
        )
    }
    pub fn from_handoffs(
        left: &epoch::Transition,
        right: &epoch::Transition,
        prefix: &[epoch::Transition],
    ) -> Result<Self> {
        let history = |proof: &epoch::Transition| {
            let mut epochs = prefix.to_vec();
            epochs.push(proof.clone());
            CertifiedHistory {
                bft: proof.closing.bft.clone(),
                statement: proof.closing.statement.clone(),
                approvals: proof.closing.approvals.clone(),
                headers: proof.closing.headers.clone(),
                epochs,
            }
        };
        Self::canonical(history(left), history(right))
    }
    pub fn id(&self) -> Result<Hash> {
        id(
            "authenticated-checkpoint-conflict",
            &(self.left.context_id()?, self.right.context_id()?),
        )
    }
    pub fn region(&self) -> Hash {
        self.left.statement.region
    }
    pub fn verify(&self, trust: &Trust) -> Result<()> {
        encode("incident", self)?;
        require(
            self.left.statement.region == self.right.statement.region
                && self.left.context_id()? < self.right.context_id()?,
            "incident regions differ or pair is not canonical",
        )?;
        let epoch_conflict = self.left.epochs.iter().any(|a| {
            self.right.epochs.iter().any(|b| {
                a.statement.previous_epoch == b.statement.previous_epoch
                    && a.statement.id().ok() != b.statement.id().ok()
            })
        });
        let retired_vote = |authority: &CertifiedHistory, certificate: &CertifiedHistory| {
            authority.epochs.iter().any(|p| {
                certificate.statement.epoch == p.statement.previous_epoch
                    && certificate.statement.height > p.statement.closing_height
            })
        };
        require(
            epoch_conflict
                || retired_vote(&self.left, &self.right)
                || retired_vote(&self.right, &self.left)
                || self.left.headers.iter().any(|left| {
                    self.right.headers.iter().any(|right| {
                        left.height == right.height && left.id().ok() != right.id().ok()
                    })
                }),
            "compatible certificates are not conflict evidence",
        )?;
        // This is rejection only. A structurally compatible pair cannot be an
        // incident, even if its signatures are malformed. Any potentially
        // incompatible pair still authenticates both complete histories before
        // returning success. Ordinary incoming evidence verification is separate
        // and remains mandatory before storage, deduplication or value execution.
        self.left.verify(trust)?;
        self.right.verify(trust)
    }
}
#[derive(Clone, Default, Debug, Serialize)]
pub struct Safety {
    pub regions: BTreeMap<Hash, BTreeSet<Hash>>,
}
#[derive(Debug, Serialize)]
pub struct Exposure {
    pub quarantined_coins: Vec<Hash>,
    pub retained_coin_amount: Amount,
    pub affected_historical_exports: Vec<Hash>,
    pub retained_historical_export_amount: Amount,
    pub refunds_or_balance_reversals: bool,
}
impl Safety {
    pub fn from_conflicts(conflicts: &[Conflict], trust: &Trust) -> Result<Self> {
        require(conflicts.len() <= MAX_INCIDENTS, "incident count bound")?;
        let mut result = Self::default();
        for proof in conflicts {
            proof.verify(trust)?;
            result
                .regions
                .entry(proof.region())
                .or_default()
                .insert(proof.id()?);
        }
        Ok(result)
    }
    pub fn check_region(&self, region: Hash) -> Result<()> {
        require(
            !self.regions.contains_key(&region),
            "local region has authenticated conflicting finality; new operations are quarantined",
        )
    }
    fn affected(&self, dependencies: &BTreeSet<Hash>, evidence: &VerifiedEvidence) -> Result<bool> {
        for dependency in dependencies {
            if self
                .regions
                .contains_key(&evidence.snapshot(*dependency)?.statement.region)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn check(
        &self,
        chain: &Chain,
        commands: &[Command],
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        self.check_region(chain.region)?;
        for command in commands {
            match command {
                Command::Channel(command) => {
                    let empty = channels::Book::default();
                    let book = chain
                        .ledger
                        .channel_state
                        .as_ref()
                        .map(|s| &s.book)
                        .unwrap_or(&empty);
                    let deps =
                        book.retained_dependencies(&chain.ledger, &command.action.intent.action);
                    require(
                        !self.affected(&deps, evidence)?,
                        "channel depends on quarantined finality",
                    )?;
                }
                Command::Reconfigure(_) => {} // Local-region quarantine was checked above.
                Command::Spend(signed) => {
                    for input in &signed.intent.inputs {
                        if let Some(coin) = chain.ledger.coins.get(input) {
                            require(!self.affected(&coin.dependencies,evidence)?,"input depends on quarantined finality; retained assets cannot be newly spent or exported")?;
                        }
                    }
                }
                Command::Import { snapshot, export } => {
                    let record = evidence.export(*snapshot, *export)?;
                    require(
                        !self
                            .regions
                            .contains_key(&evidence.snapshot(*snapshot)?.statement.region)
                            && !self.affected(&record.dependencies, evidence)?,
                        "new import depends on quarantined finality",
                    )?;
                }
            }
        }
        Ok(())
    }
    pub fn exposure(&self, chain: &Chain, evidence: &VerifiedEvidence) -> Result<Exposure> {
        let local = self.regions.contains_key(&chain.region);
        let mut coins = vec![];
        let mut amount = Amount::ZERO;
        let mut exports = vec![];
        let mut exported = Amount::ZERO;
        for (id, coin) in &chain.ledger.coins {
            if local || self.affected(&coin.dependencies, evidence)? {
                coins.push(*id);
                amount = add(amount, coin.payment.amount)?;
            }
        }
        for (id, record) in &chain.ledger.exports {
            if local || self.affected(&record.dependencies, evidence)? {
                exports.push(*id);
                exported = add(exported, record.recipient.amount)?;
            }
        }
        Ok(Exposure {
            quarantined_coins: coins,
            retained_coin_amount: amount,
            affected_historical_exports: exports,
            retained_historical_export_amount: exported,
            refunds_or_balance_reversals: false,
        })
    }
}
