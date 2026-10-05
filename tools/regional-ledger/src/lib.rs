//! Bounded, incompatible, fixture-only generic regional ledger candidate.
//! No existing genesis, live assets, BFT protocol or production mode.
use rld_core::{validate_ed25519_public_key, verify_bytes, AdmissionHash32 as Hash, Amount};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_BLOCKS: usize = 256;
pub const MAX_SNAPSHOTS: usize = 64;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_COMMANDS: usize = 16;
pub const MAX_COINS: usize = 4096;
const DOMAIN: &str = "RLD-REGIONAL-FIXTURE-V1";
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(msg.into())
    }
}
fn encode<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>> {
    let mut bytes = format!("{DOMAIN}:{domain}\0").into_bytes();
    bytes.extend(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    require(bytes.len() <= MAX_BYTES, "encoded evidence exceeds bound")?;
    Ok(bytes)
}
pub fn id<T: Serialize>(domain: &str, value: &T) -> Result<Hash> {
    Ok(Hash(Sha256::digest(encode(domain, value)?).into()))
}
fn add(a: Amount, b: Amount) -> Result<Amount> {
    a.checked_add(b).map_err(|e| e.to_string())
}
fn sum(mut values: impl Iterator<Item = Amount>) -> Result<Amount> {
    values.try_fold(Amount::ZERO, add)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Currency {
    pub format: String,
    pub fixture_only: bool,
    pub implementation: Hash,
    pub origin: String,
    pub authority: String,
    pub cap: Amount,
    pub block_reward: Amount,
    pub maturity: u64,
    pub signature: String,
}
impl Currency {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode(
            "currency",
            &(
                &self.format,
                self.fixture_only,
                self.implementation,
                &self.origin,
                &self.authority,
                self.cap,
                self.block_reward,
                self.maturity,
            ),
        )
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(Hash(Sha256::digest(self.bytes()?).into()))
    }
    pub fn verify(&self, trusted_authority: &str, pin: Hash) -> Result<()> {
        require(
            self.format == DOMAIN
                && self.fixture_only
                && self.implementation == implementation()?
                && self.authority == trusted_authority
                && self.id()? == pin
                && !pin.is_zero(),
            "untrusted currency or non-fixture profile",
        )?;
        validate_ed25519_public_key(&self.authority)?;
        name(&self.origin)?;
        require(
            self.cap.0 > 0
                && self.cap <= Amount::TOTAL_SUPPLY
                && self.block_reward.0 > 0
                && self.block_reward <= self.cap
                && (1..=100).contains(&self.maturity),
            "invalid issuance or maturity",
        )?;
        verify_bytes(&self.authority, &self.bytes()?, &self.signature)
    }
}
pub fn implementation() -> Result<Hash> {
    id(
        "implementation",
        &(
            env!("RLD_REGIONAL_SOURCE"),
            rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
        ),
    )
}
fn name(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && value.len() <= 32
            && value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
        "invalid regional label",
    )
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub currency: Hash,
    pub region: String,
    pub rules: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_rules: Option<Hash>,
    pub validators: Vec<String>,
    pub signature: String,
}
impl Admission {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if crate::paged_bft::is_profile(&self.rules) {
            return encode(
                "paged-bft-admission-v1",
                &(
                    self.currency,
                    &self.region,
                    &self.rules,
                    self.value_rules,
                    &self.validators,
                ),
            );
        }
        if let Some(value_rules) = self.value_rules {
            return encode(
                "value-channel-admission-v1",
                &(
                    self.currency,
                    &self.region,
                    &self.rules,
                    value_rules,
                    &self.validators,
                ),
            );
        }
        encode(
            "admission",
            &(self.currency, &self.region, &self.rules, &self.validators),
        )
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(Hash(Sha256::digest(self.bytes()?).into()))
    }
    pub fn verify(&self, currency: &Currency) -> Result<()> {
        name(&self.region)?;
        require(
            self.currency == currency.id()?
                && (self.rules == DOMAIN
                    || bft::is_profile(&self.rules)
                    || segmented::is_profile(&self.rules))
                && if channels::is_profile(&self.rules) {
                    self.value_rules
                        == Some(if crate::paged_bft::is_profile(&self.rules) {
                            crate::paged_bft::rules_hash()?
                        } else {
                            channels::profile_hash()?
                        })
                } else {
                    self.value_rules.is_none()
                }
                && self.validators.len() == 4
                && self.validators.windows(2).all(|v| v[0] < v[1]),
            "wrong admission identity, rules or validator set",
        )?;
        for key in &self.validators {
            validate_ed25519_public_key(key)?;
        }
        verify_bytes(&currency.authority, &self.bytes()?, &self.signature)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub currency: Currency,
    pub admissions: Vec<Admission>,
}
#[derive(Clone)]
pub struct Trust {
    currency: Currency,
    regions: BTreeMap<Hash, Admission>,
    binding: Hash,
}
impl Trust {
    pub fn verify(package: &Bootstrap, authority: &str, pin: Hash) -> Result<Self> {
        package.currency.verify(authority, pin)?;
        require(
            !package.admissions.is_empty() && package.admissions.len() <= 16,
            "admission bound",
        )?;
        let mut regions = BTreeMap::new();
        let mut labels = BTreeSet::new();
        for a in &package.admissions {
            a.verify(&package.currency)?;
            require(labels.insert(a.region.clone()), "duplicate regional label")?;
            regions.insert(a.id()?, a.clone());
        }
        require(
            labels.contains(&package.currency.origin),
            "origin admission missing",
        )?;
        if package
            .admissions
            .iter()
            .any(|a| channels::is_profile(&a.rules))
        {
            require(
                package
                    .admissions
                    .iter()
                    .any(|a| a.region == package.currency.origin && channels::is_profile(&a.rules))
                    && package.currency.cap == Amount::TOTAL_SUPPLY
                    && package.currency.block_reward
                        == rld_pow::subsidy(1).map_err(|e| e.to_string())?,
                "channel currency requires exact origin reserve-era issuance admission",
            )?;
        }
        Ok(Self {
            binding: id("verified-trust", &(&package.currency, &regions))?,
            currency: package.currency.clone(),
            regions,
        })
    }
    pub fn region(&self, id: Hash) -> Result<&Admission> {
        self.regions
            .get(&id)
            .ok_or("unknown regional genesis".into())
    }
    pub fn named(&self, label: &str) -> Result<Hash> {
        self.regions
            .iter()
            .find(|(_, a)| a.region == label)
            .map(|(id, _)| *id)
            .ok_or("unknown region".into())
    }
    pub fn currency(&self) -> Result<Hash> {
        self.currency.id()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    pub owner: String,
    pub amount: Amount,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub currency: Hash,
    pub region: Hash,
    pub inputs: Vec<Hash>,
    pub outputs: Vec<Payment>,
    pub fee: Amount,
    pub destination: Option<Hash>,
    pub remote: Option<Payment>,
    pub destination_fee: Amount,
    pub valid_through: u64,
}
impl Intent {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("owner-intent", self)
    }
    pub fn id(&self) -> Result<Hash> {
        id("owner-intent", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub key: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedIntent {
    pub intent: Intent,
    pub approvals: Vec<Approval>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Command {
    Spend(Box<SignedIntent>),
    Import { snapshot: Hash, export: Hash },
    Reconfigure(Box<joint_epoch::Plan>),
    Channel(Box<channels::NativeCommand>),
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coin {
    pub payment: Payment,
    pub created: u64,
    pub mature: u64,
    pub dependencies: BTreeSet<Hash>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub channel_dependencies: BTreeSet<Hash>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub id: Hash,
    pub source: Hash,
    pub destination: Hash,
    pub recipient: Payment,
    pub destination_fee: Amount,
    pub height: u64,
    pub dependencies: BTreeSet<Hash>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub channel_dependencies: BTreeSet<Hash>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub coins: BTreeMap<Hash, Coin>,
    pub exports: BTreeMap<Hash, Export>,
    pub imports: BTreeMap<Hash, Hash>,
    pub minted: Amount,
    pub received: Amount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<Box<channels::NativeState>>,
}
impl Ledger {
    pub fn root(&self) -> Result<Hash> {
        state_proof::Commitment::from_ledger(self)?.hash()
    }
    pub fn audit(&self) -> Result<()> {
        for coin in self.coins.values() {
            channels::dependency_bound(&coin.dependencies, &coin.channel_dependencies)?;
        }
        for export in self.exports.values() {
            channels::dependency_bound(&export.dependencies, &export.channel_dependencies)?;
        }
        if let Some(state) = &self.channel_state {
            return state.book.audit(self, &state.declaration);
        }
        require(
            self.coins.len() <= MAX_COINS
                && self.exports.len() <= MAX_COINS
                && self.imports.len() <= MAX_COINS,
            "permanent ledger index full",
        )?;
        let liquid = sum(self.coins.values().map(|c| c.payment.amount))?;
        let outbound = sum(self.exports.values().map(|e| e.recipient.amount))?;
        require(
            add(self.minted, self.received)? == add(liquid, outbound)?,
            "regional conservation failure",
        )
    }
    fn output(
        &mut self,
        tx: Hash,
        index: u32,
        payment: Payment,
        height: u64,
        mature: u64,
        deps: &BTreeSet<Hash>,
    ) -> Result<()> {
        self.output_with_channels(tx, index, payment, height, mature, deps, &BTreeSet::new())
    }
    #[allow(clippy::too_many_arguments)] // Exact immutable lineage accompanies every value output.
    fn output_with_channels(
        &mut self,
        tx: Hash,
        index: u32,
        payment: Payment,
        height: u64,
        mature: u64,
        deps: &BTreeSet<Hash>,
        channel_deps: &BTreeSet<Hash>,
    ) -> Result<()> {
        channels::dependency_bound(deps, channel_deps)?;
        validate_ed25519_public_key(&payment.owner)?;
        require(payment.amount.0 > 0, "zero output")?;
        let key = id("output", &(tx, index))?;
        require(!self.coins.contains_key(&key), "output collision")?;
        self.coins.insert(
            key,
            Coin {
                payment,
                created: height,
                mature,
                dependencies: deps.clone(),
                channel_dependencies: channel_deps.clone(),
            },
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub currency: Hash,
    pub region: Hash,
    pub parent: Hash,
    pub anchor: Option<Hash>,
    pub height: u64,
    pub miner: String,
    pub commands: Hash,
    pub state: Hash,
    pub nonce: u64,
}
impl Header {
    pub fn id(&self) -> Result<Hash> {
        id("block", self)
    }
    pub fn work_valid(&self) -> Result<bool> {
        Ok(self.id()?.0[0] == 0)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub commands: Vec<Command>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub currency: Hash,
    pub region: Hash,
    pub height: u64,
    pub block: Hash,
    pub state: Hash,
    pub previous: Option<Hash>,
    pub epoch: Hash,
}
impl Statement {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        encode("unanimous-checkpoint", self)
    }
    pub fn id(&self) -> Result<Hash> {
        id("unanimous-checkpoint", self)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bft: Option<bft::Certificate>,
    pub statement: Statement,
    pub approvals: Vec<Approval>,
    pub blocks: Vec<Block>,
    pub epochs: Vec<epoch::Transition>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub snapshots: Vec<Snapshot>,
}
#[derive(Clone, Default)]
pub struct VerifiedEvidence {
    snapshots: BTreeMap<Hash, (Snapshot, Ledger)>,
    pub(crate) epochs: epoch::Registry,
    trust_binding: Option<Hash>,
}
impl VerifiedEvidence {
    pub(crate) fn check_trust(&self, trust: &Trust) -> Result<()> {
        require(
            self.trust_binding
                .is_none_or(|binding| binding == trust.binding),
            "verified evidence belongs to another exact trust set",
        )
    }
    pub fn verify(evidence: &Evidence, trust: &Trust) -> Result<Self> {
        require(evidence.snapshots.len() <= MAX_SNAPSHOTS, "snapshot bound")?;
        encode("evidence", evidence)?;
        let mut result = Self {
            trust_binding: Some(trust.binding),
            ..Self::default()
        };
        for snapshot in &evidence.snapshots {
            result.add(snapshot.clone(), trust)?;
        }
        Ok(result)
    }
    pub fn add(&mut self, snapshot: Snapshot, trust: &Trust) -> Result<Hash> {
        self.check_trust(trust)?;
        segmented::shape(&snapshot, trust)?;
        let statement = &snapshot.statement;
        let sid = statement.id()?;
        if let Some((old, _)) = self.snapshots.get(&sid) {
            if old != &snapshot {
                require(
                    bft::is_profile(&trust.region(statement.region)?.rules)
                        && old.statement == snapshot.statement
                        && old.blocks == snapshot.blocks
                        && (old.epochs == snapshot.epochs
                            || crate::bft::is_joint(&trust.region(statement.region)?.rules)
                                && old
                                    .epochs
                                    .iter()
                                    .map(|p| p.statement.id())
                                    .collect::<Result<Vec<_>>>()?
                                    == snapshot
                                        .epochs
                                        .iter()
                                        .map(|p| p.statement.id())
                                        .collect::<Result<Vec<_>>>()?)
                        && snapshot.approvals.is_empty(),
                    "inconsistent duplicate snapshot",
                )?;
                let mut checked = self.epochs.clone();
                for proof in &snapshot.epochs {
                    checked.install(proof.clone(), trust, &self.snapshots)?;
                }
                let keys = checked.checkpoint_keys(trust, statement)?;
                bft::checkpoint_auth(
                    statement,
                    &snapshot.approvals,
                    snapshot.bft.as_ref(),
                    &snapshot
                        .blocks
                        .iter()
                        .map(|b| b.header.clone())
                        .collect::<Vec<_>>(),
                    &keys,
                    trust,
                )?;
            }
            return Ok(sid);
        }
        require(
            self.snapshots.len() < MAX_SNAPSHOTS && snapshot.blocks.len() <= MAX_BLOCKS,
            "snapshot or block bound",
        )?;
        let mut prepared_epochs = self.epochs.clone();
        require(
            snapshot.epochs.len() <= epoch::MAX_EPOCHS,
            "snapshot epoch bound",
        )?;
        for proof in &snapshot.epochs {
            require(
                proof.statement.region == statement.region,
                "snapshot carries wrong-region epoch",
            )?;
            prepared_epochs.install(proof.clone(), trust, &self.snapshots)?;
        }
        let keys = prepared_epochs.checkpoint_keys(trust, statement)?;
        let all = prepared_epochs.proofs(statement.region);
        let count = if statement.epoch == epoch::Registry::initial(trust, statement.region)? {
            0
        } else {
            all.iter()
                .position(|p| p.statement.id().ok() == Some(statement.epoch))
                .ok_or("unknown checkpoint epoch context")?
                + 1
        };
        require(
            snapshot
                .epochs
                .iter()
                .map(|p| p.statement.id())
                .collect::<Result<Vec<_>>>()?
                == all[..count]
                    .iter()
                    .map(|p| p.statement.id())
                    .collect::<Result<Vec<_>>>()?,
            "snapshot omits or overstates its epoch authority chain",
        )?;
        bft::checkpoint_auth(
            statement,
            &snapshot.approvals,
            snapshot.bft.as_ref(),
            &snapshot
                .blocks
                .iter()
                .map(|b| b.header.clone())
                .collect::<Vec<_>>(),
            &keys,
            trust,
        )?;
        require(
            statement.currency == trust.currency()? && statement.height > 0,
            "invalid checkpoint identity",
        )?;
        // One compatible, monotonic certificate chain per region. No conflict
        // resolution or BFT view changes are manufactured by this prototype.
        let latest = self
            .snapshots
            .iter()
            .filter(|(_, (s, _))| s.statement.region == statement.region)
            .max_by_key(|(_, (s, _))| s.statement.height);
        require(
            statement.previous == latest.map(|(id, _)| *id),
            "checkpoint is stale, conflicting or missing predecessor",
        )?;
        if bft::is_profile(&trust.region(statement.region)?.rules) {
            let parent_height = latest.map(|(_, (s, _))| s.statement.height).unwrap_or(0);
            require(
                parent_height.checked_add(1) == Some(statement.height),
                "BFT evidence skipped its certified predecessor",
            )?;
        }
        if let Some((_, (old, _))) = latest {
            require(
                statement.height > old.statement.height
                    && (crate::segmented::is_profile(&trust.region(statement.region)?.rules)
                        || crate::paged_bft::is_profile(&trust.region(statement.region)?.rules)
                        || snapshot.blocks.starts_with(&old.blocks)),
                "checkpoint fork or rollback",
            )?;
        }
        let chain = if crate::bft::is_joint(&trust.region(statement.region)?.rules) {
            // Keep prepared authority separate until every tail/value check passes.
            let mut staged = self.clone();
            staged.epochs = prepared_epochs.clone();
            staged.replay_extension(&snapshot, trust)?
        } else {
            self.replay_extension(&snapshot, trust)?
        };
        require(
            chain.statement(trust)? == *statement,
            "checkpoint differs from replayed history",
        )?;
        self.epochs = prepared_epochs;
        self.trust_binding = Some(trust.binding);
        self.snapshots.insert(sid, (snapshot, chain.ledger));
        Ok(sid)
    }
    /// Reuse only this process's fully replayed exact predecessor. Serialized
    /// state never supplies this starting ledger: cold verification builds it
    /// from genesis and authenticates every new block before retaining it.
    pub(crate) fn replay_extension(&self, snapshot: &Snapshot, trust: &Trust) -> Result<Chain> {
        self.check_trust(trust)?;
        require(
            snapshot.statement.currency == trust.currency()? && snapshot.blocks.len() <= MAX_BLOCKS,
            "replay extension identity or block bound",
        )?;
        if crate::paged_bft::is_profile(&trust.region(snapshot.statement.region)?.rules) {
            return crate::paged_bft::replay(snapshot, trust, self);
        }
        if crate::segmented::is_profile(&trust.region(snapshot.statement.region)?.rules) {
            return segmented::replay(snapshot, trust, self);
        }
        let mut chain = if let Some(previous) = snapshot.statement.previous {
            let (parent, ledger) = self
                .snapshots
                .get(&previous)
                .ok_or("missing replayed predecessor checkpoint")?;
            require(
                parent.statement.region == snapshot.statement.region
                    && parent.statement.currency == snapshot.statement.currency
                    && snapshot.blocks.starts_with(&parent.blocks),
                "extension differs from exact replayed prefix",
            )?;
            Chain {
                region: parent.statement.region,
                trust_binding: trust.binding,
                currency: trust.currency()?,
                prefix_height: 0,
                prefix_tip: parent.statement.region,
                segmented: false,
                blocks: parent.blocks.clone(),
                ledger: ledger.clone(),
                // The retained snapshot's last block precedes installation of
                // that snapshot. Its next block must still install the anchor
                // through the normal predecessor and finality checks.
                finalized: parent.statement.previous,
                epoch: parent.statement.epoch,
            }
        } else {
            Chain::new(snapshot.statement.region, trust)?
        };
        if crate::bft::is_joint(&trust.region(chain.region)?.rules) {
            chain.epoch = joint_epoch::next_epoch(&chain, trust, self)?;
        }
        let start = chain.blocks.len();
        require(
            start < snapshot.blocks.len(),
            "checkpoint extension has no new block",
        )?;
        for block in &snapshot.blocks[start..] {
            chain.accept(block.clone(), trust, self)?;
        }
        if crate::bft::is_joint(&trust.region(chain.region)?.rules) {
            require(
                chain.epoch == snapshot.statement.epoch,
                "joint replay epoch mismatch",
            )?;
        } else {
            chain.epoch = snapshot.statement.epoch;
        }
        Ok(chain)
    }
    pub fn descends_from(&self, mut current: Hash, ancestor: Hash) -> Result<bool> {
        for _ in 0..MAX_SNAPSHOTS {
            if current == ancestor {
                return Ok(true);
            }
            match self.snapshot(current)?.statement.previous {
                Some(previous) => current = previous,
                None => return Ok(false),
            }
        }
        Err("checkpoint ancestry bound".into())
    }
    pub fn epoch_proofs(&self, region: Hash) -> Vec<epoch::Transition> {
        self.epochs.proofs(region)
    }
    pub fn epoch_state(
        &self,
        trust: &Trust,
        region: Hash,
    ) -> Result<(Hash, u64, Vec<String>, u64)> {
        self.check_trust(trust)?;
        self.epochs.latest(trust, region)
    }
    pub fn install_epoch(&mut self, proof: epoch::Transition, trust: &Trust) -> Result<Hash> {
        self.check_trust(trust)?;
        let ident = self.epochs.install(proof, trust, &self.snapshots)?;
        self.trust_binding = Some(trust.binding);
        Ok(ident)
    }
    pub fn snapshot(&self, sid: Hash) -> Result<&Snapshot> {
        self.snapshots
            .get(&sid)
            .map(|(s, _)| s)
            .ok_or("missing verified source checkpoint".into())
    }
    pub fn export(&self, sid: Hash, eid: Hash) -> Result<&Export> {
        self.snapshots
            .get(&sid)
            .ok_or("missing dependency checkpoint")?
            .1
            .exports
            .get(&eid)
            .ok_or("export absent from finalized source".into())
    }
    pub fn prove_state(
        &self,
        sid: Hash,
        collection: state_proof::Collection,
        key: Hash,
        trust: &Trust,
    ) -> Result<state_proof::Proof> {
        self.check_trust(trust)?;
        let (snapshot, ledger) = self
            .snapshots
            .get(&sid)
            .ok_or("missing verified source checkpoint")?;
        let proof = state_proof::Proof::from_ledger(ledger, collection, key)?;
        proof.verify(snapshot.statement.state, collection, key)?;
        Ok(proof)
    }
    pub fn check_state_proof(
        &self,
        sid: Hash,
        collection: state_proof::Collection,
        key: Hash,
        proof: &state_proof::Proof,
        trust: &Trust,
    ) -> Result<Option<state_proof::Value>> {
        self.check_trust(trust)?;
        proof.verify(self.snapshot(sid)?.statement.state, collection, key)
    }
}
#[derive(Clone)]
pub struct Chain {
    pub region: Hash,
    trust_binding: Hash,
    currency: Hash,
    prefix_height: u64,
    prefix_tip: Hash,
    segmented: bool,
    pub blocks: Vec<Block>,
    pub ledger: Ledger,
    pub finalized: Option<Hash>,
    pub epoch: Hash,
}
impl Chain {
    pub fn new(region: Hash, trust: &Trust) -> Result<Self> {
        trust.region(region)?;
        Ok(Self {
            region,
            trust_binding: trust.binding,
            currency: trust.currency()?,
            prefix_height: 0,
            prefix_tip: region,
            segmented: crate::segmented::is_profile(&trust.region(region)?.rules)
                || crate::paged_bft::is_profile(&trust.region(region)?.rules),
            blocks: vec![],
            ledger: Ledger::default(),
            finalized: None,
            epoch: epoch::Registry::initial(trust, region)?,
        })
    }
    pub fn height(&self) -> u64 {
        self.prefix_height + self.blocks.len() as u64
    }
    pub fn tip(&self) -> Result<Hash> {
        self.blocks
            .last()
            .map(|b| b.header.id())
            .unwrap_or(Ok(self.prefix_tip))
    }
    pub fn install(&mut self, sid: Hash, evidence: &VerifiedEvidence) -> Result<()> {
        self.check_install(sid, evidence)?;
        let tip = self.tip()?;
        let height = self.height();
        if self.segmented {
            self.prefix_height = height;
            self.prefix_tip = tip;
            self.blocks.clear();
        }
        self.finalized = Some(sid);
        Ok(())
    }
    pub fn snapshot_base(&self) -> Option<Hash> {
        if self.segmented {
            self.finalized
        } else {
            None
        }
    }
    pub fn is_segmented(&self) -> bool {
        self.segmented
    }
    fn check_install(&self, sid: Hash, evidence: &VerifiedEvidence) -> Result<()> {
        require(
            evidence
                .trust_binding
                .is_none_or(|b| b == self.trust_binding),
            "checkpoint exact trust binding differs",
        )?;
        let snapshot = evidence.snapshot(sid)?;
        if self.segmented {
            return require(
                snapshot.base == self.finalized
                    && snapshot.statement.currency == self.currency
                    && snapshot.statement
                        == self.statement_from_currency(snapshot.statement.currency)?
                    && snapshot.blocks == self.blocks,
                "segmented checkpoint differs from exact local segment",
            );
        }
        require(
            snapshot.statement.region == self.region && self.blocks.starts_with(&snapshot.blocks),
            "checkpoint does not cover this local history",
        )?;
        require(
            snapshot.statement.previous == self.finalized,
            "local checkpoint predecessor mismatch",
        )?;
        Ok(())
    }
    pub fn statement(&self, trust: &Trust) -> Result<Statement> {
        require(
            trust.binding == self.trust_binding,
            "chain exact trust binding differs",
        )?;
        self.statement_from_currency(trust.currency()?)
    }
    fn statement_from_currency(&self, currency: Hash) -> Result<Statement> {
        Ok(Statement {
            currency,
            region: self.region,
            height: self.height(),
            block: self.tip()?,
            state: self.ledger.root()?,
            previous: self.finalized,
            epoch: self.epoch,
        })
    }
    fn execute(
        &self,
        commands: &[Command],
        miner: &str,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Ledger> {
        self.execute_with_authorization(commands, miner, trust, evidence, true, self.finalized)
    }
    fn execute_with_authorization(
        &self,
        commands: &[Command],
        miner: &str,
        trust: &Trust,
        evidence: &VerifiedEvidence,
        complete: bool,
        finalized: Option<Hash>,
    ) -> Result<Ledger> {
        require(
            trust.binding == self.trust_binding,
            "chain execution trust binding differs",
        )?;
        execution::Execution {
            region: self.region,
            height: self.height(),
            tip: self.tip()?,
            ledger: &self.ledger,
        }
        .execute(commands, miner, trust, evidence, complete, finalized)
    }
    /// Validate one owner's approval through the same execution rules, but
    /// never expose a block template or mutate native state for partial consent.
    pub(crate) fn validate_partial_owner(
        &self,
        signed: SignedIntent,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        require(self.blocks.len() < MAX_BLOCKS, "history bound")?;
        let owner = signed
            .approvals
            .first()
            .ok_or("partial approval missing")?
            .key
            .clone();
        self.execute_with_authorization(
            &[Command::Spend(Box::new(signed))],
            &owner,
            trust,
            evidence,
            false,
            self.finalized,
        )?;
        Ok(())
    }
    pub fn template(
        &self,
        commands: Vec<Command>,
        miner: String,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<Block> {
        require(self.blocks.len() < MAX_BLOCKS, "history bound")?;
        let next_epoch = joint_epoch::next_epoch(self, trust, evidence)?;
        require(
            next_epoch == self.epoch,
            "joint template needs installed activation",
        )?;
        let ledger = self.execute(&commands, &miner, trust, evidence)?;
        Ok(Block {
            header: Header {
                currency: trust.currency()?,
                region: self.region,
                parent: self.tip()?,
                anchor: self.finalized,
                height: self.height() + 1,
                miner,
                commands: id("commands", &commands)?,
                state: ledger.root()?,
                nonce: 0,
            },
            commands,
        })
    }
    pub fn accept(
        &mut self,
        block: Block,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        encode("block", &block)?;
        evidence.check_trust(trust)?;
        let next_epoch = joint_epoch::next_epoch(self, trust, evidence)?;
        require(
            next_epoch == self.epoch,
            "ordinary joint chain needs explicit installed epoch event",
        )?;
        let finalized = if block.header.anchor != self.finalized {
            let anchor = block.header.anchor.ok_or("checkpoint rollback")?;
            self.check_install(anchor, evidence)?;
            Some(anchor)
        } else {
            self.finalized
        };
        require(
            self.blocks.len() < MAX_BLOCKS || (self.segmented && finalized != self.finalized),
            "history bound",
        )?;
        require(
            block.header.currency == trust.currency()?
                && block.header.region == self.region
                && block.header.parent == self.tip()?
                && block.header.height == self.height() + 1
                && block.header.commands == id("commands", &block.commands)?
                && block.header.work_valid()?,
            "invalid block identity, order, commitment or work",
        )?;
        let ledger = self.execute_with_authorization(
            &block.commands,
            &block.header.miner,
            trust,
            evidence,
            true,
            finalized,
        )?;
        require(
            ledger.root()? == block.header.state,
            "replayed state root mismatch",
        )?;
        // All fallible validation precedes mutation. In particular a rejected
        // tail cannot advance finality or mutate an input/import reservation.
        let old_tip = self.tip()?;
        let old_height = self.height();
        if self.segmented && finalized != self.finalized {
            self.prefix_height = old_height;
            self.prefix_tip = old_tip;
            self.blocks.clear();
        }
        self.blocks.push(block);
        self.ledger = ledger;
        self.finalized = finalized;
        self.epoch = next_epoch;
        #[cfg(test)]
        tests::native_prefix::note_block_replay();
        Ok(())
    }
}
pub fn mine(block: &mut Block) -> Result<()> {
    while !block.header.work_valid()? {
        block.header.nonce = block.header.nonce.checked_add(1).ok_or("nonce exhausted")?;
    }
    Ok(())
}

/// Evidence-set accounting, not a global live balance oracle. Input chains must
/// be compatible replayed histories; historical exports are counted only once.
pub fn conservation(chains: &[Chain]) -> Result<(Amount, Amount, Amount)> {
    let (issued, liquid, escrow, pending) = conservation_with_escrow(chains)?;
    require(
        escrow.is_zero(),
        "legacy three-bucket query cannot omit channel escrow",
    )?;
    Ok((issued, liquid, pending))
}
pub fn conservation_with_escrow(chains: &[Chain]) -> Result<(Amount, Amount, Amount, Amount)> {
    let mut regions = BTreeSet::new();
    let mut issued = Amount::ZERO;
    let mut liquid = Amount::ZERO;
    let mut escrow = Amount::ZERO;
    let mut exports = BTreeMap::new();
    let mut imports = BTreeSet::new();
    for chain in chains {
        require(
            regions.insert(chain.region),
            "duplicate region in accounting",
        )?;
        chain.ledger.audit()?;
        if let Some(state) = &chain.ledger.channel_state {
            escrow = add(escrow, state.book.locked()?)?;
        }
        issued = add(issued, chain.ledger.minted)?;
        liquid = add(
            liquid,
            sum(chain.ledger.coins.values().map(|c| c.payment.amount))?,
        )?;
        for (id, export) in &chain.ledger.exports {
            require(
                exports.insert(*id, export).is_none(),
                "duplicate export identity",
            )?;
        }
        for id in chain.ledger.imports.keys() {
            require(imports.insert(*id), "export imported more than once")?;
        }
    }
    for imported in &imports {
        require(
            exports.contains_key(imported),
            "incomplete compatible evidence set",
        )?;
    }
    let pending = sum(exports
        .iter()
        .filter(|(id, _)| !imports.contains(id))
        .map(|(_, e)| e.recipient.amount))?;
    require(
        issued == add(add(liquid, escrow)?, pending)?,
        "global evidence-set conservation failure",
    )?;
    Ok((issued, liquid, escrow, pending))
}
pub mod bft;
mod bft_epoch;
pub mod bft_network;
pub mod carriage;
pub mod channel_conflict;
pub mod channel_owner;
pub mod channel_receipt;
pub mod channel_state_witness;
pub mod channels;
pub mod cold_plan;
pub mod conflict;
pub mod contact;
pub mod epoch;
mod execution;
pub mod history;
pub mod history_archive;
pub mod joint_epoch;
pub mod joint_roles;
pub mod keystore;
pub mod retained_pages;
pub mod segmented;
pub mod signer;
mod state_index;
pub mod state_proof;
pub mod storage;
pub mod stream_archive;
pub mod stream_replay;
#[cfg(test)]
mod tests;
pub mod wallet;
pub mod wallet_agent;

pub mod paged_bft;
