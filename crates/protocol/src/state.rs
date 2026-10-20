use crate::permanent::Permanent;
use crate::table::{Key, Table};
use crate::{
    codec::{Amount, Blob, Id, encode, hash, sorted_unique, tagged},
    crypto,
    merkle::{self, Entry},
    model::*,
    proof::{self, Verifier},
};
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};
mod wire;

pub const COLLECTIONS: &[&str] = &[
    "fee_policies",
    "outputs",
    "grants",
    "segments",
    "controllers",
    "births",
    "coupon_uses",
    "families",
    "decisions",
    "redemptions",
    "services",
    "covers",
    "mints",
    "applied",
    "incidents",
    "funding",
    "resolutions",
    "counters",
];

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, minicbor::Encode)]
#[serde(deny_unknown_fields)]
#[cbor(array)]
pub struct State {
    #[n(0)]
    pub currency: Id,
    #[n(1)]
    pub domain: Id,
    #[n(2)]
    pub sequence: u64,
    #[n(3)]
    pub configuration: Configuration,
    #[n(4)]
    pub outputs: crate::utxo::Outputs,
    #[n(5)]
    pub grants: Table<Grant>,
    #[n(6)]
    pub segments: Table<Segment>,
    #[n(7)]
    pub controllers: Table<Controller>,
    #[n(8)]
    pub births: Permanent<Birth>,
    #[n(9)]
    pub coupon_uses: Table<Delegation>,
    #[n(10)]
    pub families: Table<Family>,
    #[n(11)]
    pub decisions: Permanent<Decision>,
    #[n(12)]
    pub redemptions: Permanent<Redemption>,
    #[n(13)]
    pub services: Table<Service>,
    #[n(14)]
    pub covers: Table<Cover>,
    #[n(15)]
    pub mints: Table<MintRecord>,
    #[n(16)]
    pub applied: crate::applied::AppliedIndex,
    #[n(17)]
    pub incidents: Table<Incident>,
    #[n(18)]
    pub pool_next: u32,
    #[n(19)]
    pub minted: Amount,
    #[n(20)]
    pub retired: Amount,
    #[n(21)]
    pub used_funding: Permanent<Id>,
    #[n(22)]
    pub resolutions: Permanent<Decision>,
    #[n(23)]
    pub fee_policies: Table<FeePolicy>,
}
impl State {
    fn from_wire(w: wire::StateWire) -> Result<Self> {
        let c = w.currency;
        let domain = w.domain;
        Ok(Self {
            currency: w.currency,
            domain: w.domain,
            sequence: w.sequence,
            configuration: w.configuration,
            outputs: crate::utxo::Outputs::from_sorted(c, domain, w.outputs)?,
            grants: Table::from_sorted(c, &format!("{domain}/grants"), w.grants)?,
            segments: Table::from_sorted(c, &format!("{domain}/segments"), w.segments)?,
            controllers: Table::from_sorted(c, &format!("{domain}/controllers"), w.controllers)?,
            births: Permanent::from_sorted(c, &format!("{domain}/births"), w.births)?,
            coupon_uses: Table::from_sorted(c, &format!("{domain}/coupon_uses"), w.coupon_uses)?,
            families: Table::from_sorted(c, &format!("{domain}/families"), w.families)?,
            decisions: Permanent::from_sorted(c, &format!("{domain}/decisions"), w.decisions)?,
            redemptions: Permanent::from_sorted(
                c,
                &format!("{domain}/redemptions"),
                w.redemptions,
            )?,
            services: Table::from_sorted(c, &format!("{domain}/services"), w.services)?,
            covers: Table::from_sorted(c, &format!("{domain}/covers"), w.covers)?,
            mints: Table::from_sorted(c, &format!("{domain}/mints"), w.mints)?,
            applied: crate::applied::AppliedIndex::from_sorted(
                c,
                &format!("{domain}/applied"),
                w.applied,
            )?,
            incidents: Table::from_sorted(c, &format!("{domain}/incidents"), w.incidents)?,
            pool_next: w.pool_next,
            minted: w.minted,
            retired: w.retired,
            used_funding: Permanent::from_sorted(c, &format!("{domain}/funding"), w.used_funding)?,
            resolutions: Permanent::from_sorted(
                c,
                &format!("{domain}/resolutions"),
                w.resolutions,
            )?,
            fee_policies: Table::from_sorted(c, &format!("{domain}/fee_policies"), w.fee_policies)?,
        })
    }
}
impl<'b, C> minicbor::Decode<'b, C> for State {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        c: &mut C,
    ) -> std::result::Result<Self, minicbor::decode::Error> {
        Self::from_wire(<wire::StateWire as minicbor::Decode<C>>::decode(d, c)?)
            .map_err(|_| minicbor::decode::Error::message("native table order/duplicate"))
    }
}
impl<'de> serde::Deserialize<'de> for State {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::from_wire(<wire::StateWire as serde::Deserialize>::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}

pub fn genesis_id(c: Id, g: &DomainGenesis) -> Id {
    hash("RLD-DOMAIN-GENESIS", c, &(&g.identity, &g.configuration))
}
pub fn initial_anchor(c: Id, g: &DomainGenesis) -> Id {
    let mut config = g.configuration.clone();
    config.initial_anchor = Id::ZERO;
    hash("RLD-INITIAL-DESCRIPTOR", c, &(&g.identity, config))
}
pub fn sum(parts: &[Component]) -> Result<Amount> {
    parts.iter().try_fold(Amount(0), |a, v| a.add(v.amount))
}
fn parts(parts: &[Component]) -> Result<()> {
    ensure!(
        !parts.is_empty()
            && parts.len() <= 64
            && parts.windows(2).all(|w| w[0].cover < w[1].cover)
            && parts.iter().all(|v| v.amount.0 > 0),
        "component order/count/zero"
    );
    sum(parts)?;
    Ok(())
}
fn totals<'a>(lists: impl IntoIterator<Item = &'a [Component]>) -> Result<BTreeMap<Id, Amount>> {
    let mut out: BTreeMap<Id, Amount> = BTreeMap::new();
    for list in lists {
        parts(list)?;
        for p in list {
            let n = out.get(&p.cover).copied().unwrap_or_default();
            out.insert(p.cover, n.add(p.amount)?);
        }
    }
    Ok(out)
}
fn remaining(parts: &[Component], deduct: Amount) -> Result<Vec<Component>> {
    let mut left = deduct;
    let mut result = Vec::new();
    for p in parts {
        let take = left.0.min(p.amount.0);
        left = left.sub(Amount(take))?;
        if p.amount.0 > take {
            result.push(Component {
                cover: p.cover,
                amount: Amount(p.amount.0 - take),
            })
        }
    }
    ensure!(left.0 == 0, "fee exceeds escrow");
    Ok(result)
}

impl State {
    pub fn genesis(currency: &Currency, g: &DomainGenesis) -> Result<Self> {
        currency.validate()?;
        let c = currency.id();
        let config = &g.configuration;
        config.validate()?;
        ensure!(
            g.identity.id() == config.domain
                && config.currency == c
                && config.epoch == 0
                && config.pool_epoch == 0
                && config.first_sequence == 1
                && config.initial_anchor == initial_anchor(c, g),
            "domain genesis binding"
        );
        ensure!(
            g.identity_signature.key == g.identity.key,
            "domain identity authorization"
        );
        crypto::verify_signature(
            &g.identity_signature,
            &tagged("RLD-DOMAIN-ADMISSION", c, &(&g.identity, config)),
        )?;
        Verifier { currency }.admission(config, &g.admission)?;
        crypto::identity_attestations(
            config,
            &g.attestations,
            &tagged("RLD-DOMAIN-ADMISSION", c, &(&g.identity, config)),
        )?;
        if config.domain == currency.bootstrap {
            ensure!(
                config
                    .validators
                    .iter()
                    .map(|v| v.identity)
                    .collect::<Vec<_>>()
                    == currency.bootstrap_validators,
                "bootstrap quorum differs from monetary policy"
            );
        }
        let mut state = Self {
            currency: c,
            domain: config.domain,
            sequence: 0,
            configuration: config.clone(),
            fee_policies: Table::from_sorted(
                c,
                &format!("{}/fee_policies", config.domain),
                vec![config.fee_policy.clone()],
            )?,
            outputs: crate::utxo::Outputs::new(c, config.domain),
            grants: Table::new(c, &format!("{}/grants", config.domain)),
            segments: Table::new(c, &format!("{}/segments", config.domain)),
            controllers: Table::new(c, &format!("{}/controllers", config.domain)),
            births: Permanent::new(c, &format!("{}/births", config.domain)),
            coupon_uses: Table::new(c, &format!("{}/coupon_uses", config.domain)),
            families: Table::new(c, &format!("{}/families", config.domain)),
            decisions: Permanent::new(c, &format!("{}/decisions", config.domain)),
            redemptions: Permanent::new(c, &format!("{}/redemptions", config.domain)),
            services: Table::new(c, &format!("{}/services", config.domain)),
            covers: Table::new(c, &format!("{}/covers", config.domain)),
            mints: Table::new(c, &format!("{}/mints", config.domain)),
            applied: crate::applied::AppliedIndex::new(c, &format!("{}/applied", config.domain)),
            incidents: Table::new(c, &format!("{}/incidents", config.domain)),
            pool_next: 0,
            minted: Amount(0),
            retired: Amount(0),
            used_funding: Permanent::new(c, &format!("{}/funding", config.domain)),
            resolutions: Permanent::new(c, &format!("{}/resolutions", config.domain)),
        };
        if state.domain == currency.bootstrap {
            let cover = Cover {
                families: vec![FamilyRule {
                    family: state.domain,
                    anchor: config.initial_anchor,
                    succession: vec![config.succession],
                    signatures: vec![config.signature_profile],
                    custody: config.custody_profile,
                }],
                proof_suites: vec![currency.proof.native_image, currency.proof.controller_image],
                custody_rules: vec![config.custody_profile],
                incident_rule: Id::digest(b"RLD-CONSERVATIVE-FAMILY-INCIDENT-1"),
            };
            let mut cover = cover;
            cover.proof_suites.sort();
            cover.proof_suites.dedup();
            cover.validate()?;
            let cover_id = cover.id(c);
            state.covers.insert(cover)?;
            for root in 0..crate::ROOTS {
                let creation = hash("RLD-ROOT-GRANT-CREATION", c, &(state.domain, root));
                let id = hash(
                    "RLD-GRANT-ID",
                    c,
                    &(root, 0u32, crate::SLOTS, state.domain, creation, cover_id),
                );
                state.grants.insert(Grant {
                    id,
                    root,
                    lo: 0,
                    hi: crate::SLOTS,
                    home: state.domain,
                    creation,
                    cover: cover_id,
                })?;
                state.segments.insert(Segment {
                    grant: id,
                    lo: 0,
                    hi: crate::SLOTS,
                    cursor: 0,
                    mint_anchor: hash("RLD-SEGMENT-OPEN", c, &(id, 0u32, creation, "genesis")),
                })?;
            }
        }
        state.invariants()?;
        Ok(state)
    }
    pub fn invariants(&self) -> Result<()> {
        ensure!(
            self.currency == self.configuration.currency
                && self.domain == self.configuration.domain
                && self.pool_next <= crate::KEY_COUNT,
            "state identity/counter"
        );
        self.outputs
            .commitment(self.currency, &format!("{}/outputs", self.domain))?;
        self.grants
            .commitment(self.currency, &format!("{}/grants", self.domain))?;
        self.segments
            .commitment(self.currency, &format!("{}/segments", self.domain))?;
        self.controllers
            .commitment(self.currency, &format!("{}/controllers", self.domain))?;
        self.births
            .commitment(self.currency, &format!("{}/births", self.domain))?;
        self.coupon_uses
            .commitment(self.currency, &format!("{}/coupon_uses", self.domain))?;
        self.families
            .commitment(self.currency, &format!("{}/families", self.domain))?;
        self.decisions
            .commitment(self.currency, &format!("{}/decisions", self.domain))?;
        self.redemptions
            .commitment(self.currency, &format!("{}/redemptions", self.domain))?;
        self.services
            .commitment(self.currency, &format!("{}/services", self.domain))?;
        self.covers
            .commitment(self.currency, &format!("{}/covers", self.domain))?;
        self.mints
            .commitment(self.currency, &format!("{}/mints", self.domain))?;
        self.applied
            .commitment(self.currency, &format!("{}/applied", self.domain))?;
        self.incidents
            .commitment(self.currency, &format!("{}/incidents", self.domain))?;
        self.used_funding
            .commitment(self.currency, &format!("{}/funding", self.domain))?;
        self.resolutions
            .commitment(self.currency, &format!("{}/resolutions", self.domain))?;
        self.fee_policies
            .commitment(self.currency, &format!("{}/fee_policies", self.domain))?;
        // Applied and Permanent keys are unique/ordered by their private sorted
        // constructors and duplicate-refusing append paths. No replacement or
        // removal API exists. Do not enumerate those permanent keys again here;
        // complete guest wire decoding still reconstructs every native record.
        for keys in [
            self.grants.iter().map(|v| v.id).collect::<Vec<_>>(),
            self.controllers.iter().map(|v| v.id).collect(),
            self.coupon_uses.iter().map(|v| v.coupon).collect(),
            self.families.iter().map(|v| v.id).collect(),
            self.services.iter().map(|v| v.id).collect(),
            self.covers.iter().map(|v| v.id(self.currency)).collect(),
            self.mints.iter().map(|v| v.event).collect(),
        ] {
            ensure!(sorted_unique(&keys), "state map order/duplicate")
        }
        let mut slots = Vec::new();
        for s in &self.segments {
            let g = self
                .grants
                .get(s.grant)
                .ok_or_else(|| anyhow::anyhow!("segment grant"))?;
            ensure!(
                g.home == self.domain
                    && g.root < crate::ROOTS
                    && g.lo <= s.lo
                    && s.lo <= s.cursor
                    && s.cursor < s.hi
                    && s.hi <= g.hi
                    && g.hi <= crate::SLOTS,
                "segment bounds"
            );
            slots.push((g.root, s.cursor, s.hi));
        }
        slots.sort();
        ensure!(
            slots
                .windows(2)
                .all(|w| w[0].0 != w[1].0 || w[0].2 <= w[1].1),
            "overlapping issuance"
        );
        let mut minted = BTreeSet::new();
        for m in &self.mints {
            ensure!(minted.insert((m.root, m.slot)), "duplicate root slot Mint");
            let position = slots.partition_point(|s| (s.0, s.1) <= (m.root, m.slot));
            ensure!(
                position == 0 || {
                    let s = slots[position - 1];
                    s.0 != m.root || m.slot < s.1 || m.slot >= s.2
                },
                "consumed active slot"
            );
        }
        Ok(())
    }
    pub fn collection(&self, name: &str) -> Result<Vec<Entry>> {
        let c = self.currency;
        let mut out = match name {
            "outputs" => self.outputs.entries()?,
            "grants" => self.grants.entries(),
            "segments" => self.segments.entries(),
            "controllers" => self.controllers.entries(),
            "births" => self.births.entries(c)?,
            "coupon_uses" => self.coupon_uses.entries(),
            "families" => self.families.entries(),
            "decisions" => self.decisions.entries(c)?,
            "redemptions" => self.redemptions.entries(c)?,
            "services" => self.services.entries(),
            "covers" => self.covers.entries(),
            "mints" => self.mints.entries(),
            "applied" => self.applied.entries()?,
            "incidents" => self.incidents.entries(),
            "funding" => self.used_funding.entries(c)?,
            "resolutions" => self.resolutions.entries(c)?,
            "fee_policies" => self.fee_policies.entries(),
            "counters" => vec![Entry {
                key: Id::ZERO,
                value: hash(
                    "RLD-COUNTERS",
                    c,
                    &(
                        self.sequence,
                        self.pool_next,
                        self.minted,
                        self.retired,
                        self.configuration.id(),
                    ),
                ),
            }],
            _ => bail!("unknown state collection"),
        };
        out.sort_by_key(|v| v.key);
        Ok(out)
    }
    fn table_root(&self, name: &str) -> Result<Id> {
        let tag = format!("{}/{name}", self.domain);
        match name {
            "outputs" => self.outputs.commitment(self.currency, &tag),
            "grants" => self.grants.commitment(self.currency, &tag),
            "segments" => self.segments.commitment(self.currency, &tag),
            "controllers" => self.controllers.commitment(self.currency, &tag),
            "births" => self.births.commitment(self.currency, &tag),
            "coupon_uses" => self.coupon_uses.commitment(self.currency, &tag),
            "families" => self.families.commitment(self.currency, &tag),
            "decisions" => self.decisions.commitment(self.currency, &tag),
            "redemptions" => self.redemptions.commitment(self.currency, &tag),
            "services" => self.services.commitment(self.currency, &tag),
            "covers" => self.covers.commitment(self.currency, &tag),
            "mints" => self.mints.commitment(self.currency, &tag),
            "applied" => self.applied.commitment(self.currency, &tag),
            "incidents" => self.incidents.commitment(self.currency, &tag),
            "funding" => self.used_funding.commitment(self.currency, &tag),
            "resolutions" => self.resolutions.commitment(self.currency, &tag),
            "fee_policies" => self.fee_policies.commitment(self.currency, &tag),
            "counters" => merkle::root(self.currency, &tag, &self.collection(name)?),
            _ => bail!("unknown state collection"),
        }
    }
    fn table_witness(&self, name: &str, key: Id) -> Result<merkle::Membership> {
        self.table_root(name)?;
        match name {
            "outputs" => self.outputs.witness(key),
            "grants" => self.grants.witness(key),
            "segments" => self.segments.witness(key),
            "controllers" => self.controllers.witness(key),
            "births" => self.births.witness(key),
            "coupon_uses" => self.coupon_uses.witness(key),
            "families" => self.families.witness(key),
            "decisions" => self.decisions.witness(key),
            "redemptions" => self.redemptions.witness(key),
            "services" => self.services.witness(key),
            "covers" => self.covers.witness(key),
            "mints" => self.mints.witness(key),
            "applied" => self.applied.witness(key),
            "incidents" => self.incidents.witness(key),
            "funding" => self.used_funding.witness(key),
            "resolutions" => self.resolutions.witness(key),
            "fee_policies" => self.fee_policies.witness(key),
            "counters" => {
                let entries = self.collection(name)?;
                let i = entries
                    .binary_search_by_key(&key, |e| e.key)
                    .map_err(|_| anyhow::anyhow!("missing state key"))?;
                merkle::prove(
                    self.currency,
                    &format!("{}/{name}", self.domain),
                    &entries,
                    i,
                )
            }
            _ => bail!("unknown state collection"),
        }
    }
    pub fn top(&self) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for &name in COLLECTIONS {
            out.push(Entry {
                key: hash("RLD-COLLECTION", self.currency, &(self.domain, name)),
                value: self.table_root(name)?,
            });
        }
        out.sort_by_key(|e| e.key);
        Ok(out)
    }
    pub fn root(&self) -> Result<Id> {
        merkle::root(
            self.currency,
            &format!("{}/state", self.domain),
            &self.top()?,
        )
    }
    pub fn witness(&self, collection: &str, key: Id) -> Result<StateWitness> {
        let entry = self.table_witness(collection, key)?;
        let tops = self.top()?;
        let topkey = hash("RLD-COLLECTION", self.currency, &(self.domain, collection));
        let j = tops
            .binary_search_by_key(&topkey, |v| v.key)
            .expect("collection");
        Ok(StateWitness {
            collection: collection.into(),
            entry,
            top: merkle::prove(self.currency, &format!("{}/state", self.domain), &tops, j)?,
        })
    }
    pub fn execute_batch(
        &self,
        currency: &Currency,
        predecessor: Id,
        batch: &Batch,
    ) -> Result<(Self, Checkpoint)> {
        ensure!(
            currency.id() == self.currency
                && !batch.operations.is_empty()
                && batch.operations.len() <= 64,
            "batch currency/count"
        );
        let old = self.root()?;
        let cfg = self.configuration.id();
        let seq = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("sequence exhaustion"))?;
        let mut next = self.clone();
        next.sequence = seq;
        for op in &batch.operations {
            ensure!(
                !matches!(op.command, Command::Handoff(_)) || batch.operations.len() == 1,
                "handoff must end batch"
            );
            next.apply(currency, op, old)?;
        }
        next.invariants()?;
        let header = Checkpoint {
            profile: "RLD-NATIVE-RELATION-1".into(),
            currency: self.currency,
            domain: self.domain,
            sequence: seq,
            predecessor,
            old_root: old,
            new_root: next.root()?,
            batch: hash("RLD-BATCH", self.currency, batch),
            configuration: cfg,
            material_root: hash(
                "RLD-NATIVE-MATERIAL",
                self.currency,
                &batch
                    .operations
                    .iter()
                    .map(Operation::id)
                    .collect::<Vec<_>>(),
            ),
        };
        Ok((next, header))
    }
    fn cover(&self, id: Id) -> Result<&Cover> {
        self.covers
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("missing cover definition"))
    }
    fn usable(&self, components: &[Component]) -> Result<()> {
        parts(components)?;
        for p in components {
            let cover = self.cover(p.cover)?;
            self.configuration.accepts(cover)?;
            ensure!(
                !cover.families.iter().any(|f| self
                    .incidents
                    .get_key(Key::Incident(f.family, f.anchor))
                    .is_some()),
                "quarantined cover"
            );
        }
        Ok(())
    }
    fn allocation(&self, a: &Allocation) -> Result<()> {
        a.owner.validate()?;
        self.usable(&a.components)
    }
    fn input_parts(&self, ids: &[Id], op: &Operation) -> Result<Vec<Vec<Component>>> {
        ensure!(
            !ids.is_empty() && ids.len() <= 64 && sorted_unique(ids),
            "input order/count"
        );
        let mut result = Vec::new();
        for id in ids {
            let o = self
                .outputs
                .get(*id)?
                .ok_or_else(|| anyhow::anyhow!("input missing/spent"))?;
            self.usable(&o.components)?;
            crypto::authorize(&o.owner, &op.authorizations, &op.signing_bytes())?;
            result.push(o.components.clone());
        }
        Ok(result)
    }
    fn conserve(
        &self,
        inputs: &[Vec<Component>],
        outputs: &[Vec<Component>],
        lifts: &[Lift],
    ) -> Result<()> {
        let mut a = totals(inputs.iter().map(Vec::as_slice))?;
        ensure!(
            lifts.len() <= 64 && lifts.windows(2).all(|w| w[0].from < w[1].from),
            "lift order/count"
        );
        for lift in lifts {
            ensure!(lift.from != lift.to, "identity lift");
            self.cover(lift.from)?.subset_of(self.cover(lift.to)?)?;
            ensure!(lift.amount.0 > 0, "zero lift");
            let n = a
                .get(&lift.from)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("lift unused source"))?;
            let rest = n.sub(lift.amount)?;
            if rest.0 == 0 {
                a.remove(&lift.from);
            } else {
                a.insert(lift.from, rest);
            }
            let old = a.get(&lift.to).copied().unwrap_or_default();
            a.insert(lift.to, old.add(lift.amount)?);
        }
        ensure!(
            a == totals(outputs.iter().filter(|v| !v.is_empty()).map(Vec::as_slice))?,
            "cover/amount conservation"
        );
        Ok(())
    }
    fn output(&mut self, id: Id, index: &mut u32, a: &Allocation) -> Result<()> {
        self.allocation(a)?;
        ensure!(*index < 64, "output count");
        let key = hash("RLD-OUTPUT-ID", self.currency, &(id, *index));
        ensure!(self.outputs.get(key)?.is_none(), "output ID collision");
        self.outputs.insert(Output {
            id: key,
            owner: a.owner.clone(),
            home: self.domain,
            components: a.components.clone(),
        })?;
        *index = index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("output index"))?;
        Ok(())
    }
    fn remove_inputs(&mut self, ids: &[Id]) -> Result<()> {
        for id in ids {
            self.outputs.remove(*id)?.context("input already removed")?;
        }
        Ok(())
    }
    fn fees(&self, currency: &Currency, fees: &[Fee], policy: &FeePolicy) -> Result<()> {
        policy.validate()?;
        ensure!(
            self.fee_policies.contains(policy),
            "fee policy was never authenticated locally"
        );
        ensure!(fees.len() <= 32, "fee count");
        let mut kinds = [Amount(0); 3];
        let verifier = Verifier { currency };
        for f in fees {
            if f.kind == 2 {
                let reserve = f
                    .reserve
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("archival fee requires locked reserve"))?;
                ensure!(
                    reserve.fee_policy == policy.id(self.currency)
                        && reserve.custodians == policy.archive_custodians
                        && f.payout.owner == policy.archive_owner
                        && reserve.balance == f.payout.components
                        && reserve.owner == f.payout.owner
                        && reserve.beneficiary == self.domain
                        && reserve.family == Id::ZERO
                        && reserve.capacity > 0
                        && reserve.reserved == reserve.capacity
                        && reserve.horizon > 0,
                    "archival reserve terms"
                );
                reserve.renewal_payer.validate()?;
                reserve.custodians.validate()?;
            } else {
                ensure!(f.reserve.is_none(), "unexpected service reserve");
            }
            ensure!(f.kind < 3, "fee kind");
            if f.kind == 0 {
                ensure!(
                    f.payout.owner == policy.service_owner,
                    "service fee recipient"
                );
            }
            self.allocation(&f.payout)?;
            let n = sum(&f.payout.components)?;
            kinds[f.kind as usize] = kinds[f.kind as usize].add(n)?;
            if f.kind == 1 {
                let m = f
                    .mint
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing work-author event"))?;
                ensure!(
                    m.record.owner == f.payout.owner,
                    "work-author payout changed"
                );
                if !self.mints.contains(&m.record) {
                    let p = m
                        .certified
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("prior Mint proof"))?;
                    let w = m
                        .inclusion
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("prior Mint inclusion"))?;
                    verifier.native(p)?;
                    verifier.witness(
                        &p.header,
                        "mints",
                        m.record.event,
                        hash("RLD-MINT-RECORD", self.currency, &m.record),
                        w,
                    )?;
                }
            } else {
                ensure!(f.mint.is_none(), "unexpected Mint witness");
            }
        }
        ensure!(
            kinds[0] >= policy.minimum_service
                && kinds[1] >= policy.minimum_work_author
                && kinds[2] >= policy.minimum_archive,
            "positive service/work-author/archive fees required"
        );
        Ok(())
    }
    fn add_fees(&mut self, id: Id, index: &mut u32, fees: &[Fee]) -> Result<()> {
        for f in fees {
            if f.kind == 1 {
                self.remember_mint(
                    &f.mint
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing verified Mint fact"))?
                        .record,
                )?;
            }
            if let Some(reserve) = &f.reserve {
                ensure!(
                    self.services.get(reserve.id).is_none(),
                    "reserve ID already used"
                );
                self.services.insert(reserve.clone())?;
            } else {
                self.output(id, index, &f.payout)?;
            }
        }
        Ok(())
    }
    fn remember_mint(&mut self, record: &MintRecord) -> Result<()> {
        ensure!(
            record.root < crate::ROOTS && record.slot < crate::SLOTS,
            "Mint fact range"
        );
        if let Some(old) = self.mints.get(record.event) {
            ensure!(old == record, "changed Mint event");
            return Ok(());
        }
        ensure!(
            !self
                .mints
                .iter()
                .any(|m| m.root == record.root && m.slot == record.slot),
            "conflicting Mint facts for one global slot"
        );
        self.mints.insert(record.clone())?;
        Ok(())
    }
    fn apply(&mut self, currency: &Currency, op: &Operation, committed_prestate: Id) -> Result<()> {
        ensure!(
            op.currency == self.currency && op.home == self.domain,
            "operation home/currency"
        );
        let id = op.id();
        let digest = Id::digest(&encode(op));
        if let Some(old) = self.applied.get(id)? {
            ensure!(old.digest == digest, "changed bytes for retained operation");
            self.applied.acknowledge_existing(id)?;
            return Ok(());
        }
        ensure!(
            op.covers.len() <= 64
                && op
                    .covers
                    .windows(2)
                    .all(|w| w[0].id(self.currency) < w[1].id(self.currency))
                && op.authorizations.len() <= 64,
            "operation object bounds"
        );
        for cover in &op.covers {
            cover.validate()?;
            let key = cover.id(self.currency);
            if let Some(old) = self.covers.get(key) {
                ensure!(old == cover, "cover collision")
            } else {
                self.covers.insert(cover.clone())?;
            }
        }
        let verifier = Verifier { currency };
        let mut index = 0;
        match &op.command {
            Command::LocalTransfer {
                inputs,
                outputs,
                fees,
                lifts,
            } => {
                let values = self.input_parts(inputs, op)?;
                ensure!(
                    !outputs.is_empty() && outputs.len() + fees.len() <= 64,
                    "payment output count"
                );
                self.fees(currency, fees, &self.configuration.fee_policy)?;
                for a in outputs {
                    self.allocation(a)?;
                }
                let out: Vec<_> = outputs
                    .iter()
                    .map(|a| a.components.clone())
                    .chain(fees.iter().map(|f| f.payout.components.clone()))
                    .collect();
                self.conserve(&values, &out, lifts)?;
                self.remove_inputs(inputs)?;
                for a in outputs {
                    self.output(id, &mut index, a)?;
                }
                self.add_fees(id, &mut index, fees)?;
            }
            Command::Mint(work) => {
                ensure!(work.home == self.domain, "Mint home");
                let segment_key = Key::Segment(work.grant, work.slot);
                ensure!(
                    self.segments
                        .get_key(segment_key)
                        .is_some_and(|s| s.mint_anchor == work.anchor),
                    "stale Mint frontier"
                );
                let g = self
                    .grants
                    .get(work.grant)
                    .ok_or_else(|| anyhow::anyhow!("Mint grant"))?
                    .clone();
                ensure!(
                    g.home == self.domain
                        && !self
                            .mints
                            .iter()
                            .any(|m| m.root == g.root && m.slot == work.slot),
                    "consumed Mint slot"
                );
                self.cover(g.cover)?.subset_of(self.cover(work.cover)?)?;
                self.configuration.accepts(self.cover(work.cover)?)?;
                crate::work::verify_mint(self.currency, work)?;
                self.minted = self.minted.add(Amount(crate::REWARD))?;
                self.mints.insert(MintRecord {
                    event: id,
                    grant: g.id,
                    root: g.root,
                    slot: work.slot,
                    owner: work.payout.clone(),
                })?;
                self.output(
                    id,
                    &mut index,
                    &Allocation {
                        owner: work.payout.clone(),
                        components: vec![Component {
                            cover: work.cover,
                            amount: Amount(crate::REWARD),
                        }],
                    },
                )?;
                let mut s = self
                    .segments
                    .remove_key(segment_key)?
                    .context("Mint segment absent")?;
                s.cursor = s
                    .cursor
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Mint cursor"))?;
                s.mint_anchor = hash("RLD-MINT-NEXT", self.currency, &(s.grant, work.slot, id));
                ensure!(s.cursor <= s.hi, "Mint cursor outside segment");
                if s.cursor < s.hi {
                    self.segments.insert(s)?;
                }
            }
            Command::PreparePayment {
                ticket,
                coupon,
                keys,
                material,
            } => {
                ensure!(ticket.kind == 0 && ticket.range.is_none(), "payment kind");
                self.prepare(
                    currency, op, ticket, coupon, keys, material, None, &mut index,
                )?;
            }
            Command::PrepareClaim {
                ticket,
                coupon,
                work,
                keys,
                material,
            } => {
                ensure!(
                    ticket.kind == 1
                        && ticket.range.as_ref() == Some(&work.range)
                        && work.source == self.domain
                        && work.destination == ticket.destination
                        && work.coupon == coupon.coupon.digest(self.currency)
                        && work.claimant == ticket.creator,
                    "placement intent"
                );
                crate::work::verify_claim(self.currency, work)?;
                self.prepare(
                    currency,
                    op,
                    ticket,
                    coupon,
                    keys,
                    material,
                    Some(work),
                    &mut index,
                )?;
            }
            Command::CloseDestinationCapacity(closure) => {
                verifier.coupon(&closure.coupon)?;
                verifier.native(&closure.source)?;
                let coupon = &closure.coupon.coupon;
                let id = coupon.id(self.currency);
                let cfg = &closure.source.configuration;
                ensure!(
                    coupon.destination == self.domain
                        && self.families.contains(&closure.coupon.family)
                        && closure.source.header.domain == coupon.source
                        && cfg.domain == coupon.source
                        && cfg.initial_anchor == coupon.source_family.anchor
                        && coupon.source_family.succession.contains(&cfg.succession)
                        && coupon
                            .source_family
                            .signatures
                            .contains(&cfg.signature_profile)
                        && coupon.source_family.custody == cfg.custody_profile,
                    "closure source authority"
                );
                ensure!(
                    closure.delegation.coupon == id
                        && closure.delegation.closed
                        && self.coupon_uses.get(id).is_none(),
                    "closure already consumed or source still delegated"
                );
                verifier.witness(
                    &closure.source.header,
                    "coupon_uses",
                    id,
                    hash("RLD-DELEGATION", self.currency, &closure.delegation),
                    &closure.inclusion,
                )?;
                self.coupon_uses.insert(closure.delegation.clone())?;
            }
            Command::CloseUnusedCoupon(e) => {
                verifier.coupon(e)?;
                ensure!(
                    e.coupon.source == self.domain
                        && self.coupon_uses.get(e.coupon.id(self.currency)).is_none(),
                    "coupon already used"
                );
                crypto::authorize_use(
                    &e.coupon.use_policy,
                    &op.authorizations,
                    &op.signing_bytes(),
                )?;
                crypto::authorize(
                    &e.coupon.close_policy,
                    &op.authorizations,
                    &op.signing_bytes(),
                )?;
                self.coupon_uses.insert(Delegation {
                    coupon: e.coupon.id(self.currency),
                    controller: None,
                    closed: true,
                })?;
            }
            Command::RedeemCancel(cancel) => {
                self.redeem_cancel(currency, op, cancel, &mut index)?;
            }
            Command::Import(r) | Command::Reject(r) => {
                self.destination(
                    currency,
                    op,
                    r,
                    matches!(op.command, Command::Reject(_)),
                    &mut index,
                )?;
            }
            Command::RedeemRejected(rejected) => {
                let r = &rejected.release;
                verifier.release(r)?;
                let x = &r.creation.controller;
                ensure!(
                    x.source == self.domain
                        && self.controllers.iter().any(|c| c == x)
                        && self.redemptions.get(x.id)?.is_none(),
                    "recovery source/redemption"
                );
                verifier.native(&rejected.destination)?;
                ensure!(
                    rejected.destination.header.domain == x.ticket.destination,
                    "rejection destination"
                );
                for component in &x.escrow {
                    rejected
                        .destination
                        .configuration
                        .accepts(self.cover(component.cover)?)?;
                }
                if let Some(range) = &x.ticket.range {
                    rejected
                        .destination
                        .configuration
                        .accepts(self.cover(range.cover)?)?;
                }
                let decision = Decision {
                    object: x.id,
                    coupon: x.ticket.coupon,
                    outcome: 2,
                    digest: x.ticket.digest(self.currency),
                };
                verifier.witness(
                    &rejected.destination.header,
                    "decisions",
                    x.id,
                    hash("RLD-DECISION", self.currency, &decision),
                    &rejected.decision,
                )?;
                verifier.witness(
                    &rejected.destination.header,
                    "coupon_uses",
                    x.ticket.coupon,
                    hash(
                        "RLD-DELEGATION",
                        self.currency,
                        &Delegation {
                            coupon: x.ticket.coupon,
                            controller: Some(x.id),
                            closed: true,
                        },
                    ),
                    &rejected.leaf_decision,
                )?;
                crypto::authorize(
                    &x.ticket.recovery_policy,
                    &op.authorizations,
                    &op.signing_bytes(),
                )?;
                let copies = x.clone();
                self.return_object(
                    &copies,
                    copies.ticket.recovery_fee,
                    &copies.ticket.recovery_fee_payout,
                    id,
                    &mut index,
                )?;
                self.redemptions.insert(Redemption {
                    controller: x.id,
                    kind: 2,
                    operation: id,
                })?;
            }
            Command::FundService {
                inputs,
                change,
                service,
            } => {
                ensure!(
                    service.id
                        == hash(
                            "RLD-SERVICE-ID",
                            self.currency,
                            &(self.domain, op.nonce, &service.owner)
                        )
                        && self.services.get(service.id).is_none()
                        && service.capacity > 0
                        && service.reserved == service.capacity
                        && service.family != Id::ZERO
                        && service.horizon > 0,
                    "service contract"
                );
                ensure!(
                    sum(&service.balance)?.0 > 0,
                    "service must lock existing RLD"
                );
                if service.beneficiary == self.domain {
                    ensure!(
                        service.fee_policy == self.configuration.fee_policy.id(self.currency),
                        "new local sponsorship must use current fee policy"
                    );
                }
                service.owner.validate()?;
                service.renewal_payer.validate()?;
                service.custodians.validate()?;
                crypto::authorize(&service.owner, &op.authorizations, &op.signing_bytes())?;
                self.usable(&service.balance)?;
                let values = self.input_parts(inputs, op)?;
                let out: Vec<_> = change
                    .iter()
                    .map(|a| a.components.clone())
                    .chain(std::iter::once(service.balance.clone()))
                    .collect();
                self.conserve(&values, &out, &[])?;
                self.remove_inputs(inputs)?;
                for a in change {
                    self.output(id, &mut index, a)?;
                }
                self.services.insert(service.clone())?;
            }
            Command::RenewService {
                id: service_id,
                inputs,
                change,
                added,
                horizon,
            } => {
                let mut service = self
                    .services
                    .get(*service_id)
                    .ok_or_else(|| anyhow::anyhow!("service not found"))?
                    .clone();
                crypto::authorize(
                    &service.renewal_payer,
                    &op.authorizations,
                    &op.signing_bytes(),
                )?;
                ensure!(*horizon > service.horizon, "renewal horizon");
                self.usable(added)?;
                let values = self.input_parts(inputs, op)?;
                let out: Vec<_> = change
                    .iter()
                    .map(|a| a.components.clone())
                    .chain(std::iter::once(added.clone()))
                    .collect();
                self.conserve(&values, &out, &[])?;
                let merged = totals([service.balance.as_slice(), added.as_slice()])?;
                ensure!(merged.len() <= 64, "service components");
                self.remove_inputs(inputs)?;
                for a in change {
                    self.output(id, &mut index, a)?;
                }
                service.balance = merged
                    .into_iter()
                    .map(|(cover, amount)| Component { cover, amount })
                    .collect();
                service.horizon = *horizon;
                self.services.replace(service)?;
            }
            Command::CreateFamily(f) => {
                ensure!(
                    f.coupons.len() == f.family.count as usize && f.covers.len() <= 64,
                    "family leaf/cover inventory"
                );
                for cover in &f.covers {
                    cover.validate()?;
                    self.configuration.accepts(cover)?;
                    if !self.covers.contains(cover) {
                        self.covers.insert(cover.clone())?;
                    }
                }
                verifier.native(&f.source_funding.source)?;
                let source_budget = &f.source_funding.service;
                verifier.witness(
                    &f.source_funding.source.header,
                    "services",
                    source_budget.id,
                    hash("RLD-SERVICE", self.currency, source_budget),
                    &f.source_funding.inclusion,
                )?;
                ensure!(
                    source_budget.id == f.family.source_funding
                        && source_budget.family == f.family.id
                        && source_budget.beneficiary == f.family.source
                        && f.source_funding.source.header.domain == f.family.source
                        && source_budget.capacity >= f.family.count as u64
                        && source_budget.reserved >= f.family.count as u64
                        && sum(&source_budget.balance)?.0 > 0,
                    "unfunded source sponsorship"
                );
                let mut leaves = Vec::new();
                for (index, coupon) in f.coupons.iter().enumerate() {
                    ensure!(
                        coupon.source_sponsor == source_budget.id
                            && coupon.source_fee_policy.id(self.currency)
                                == source_budget.fee_policy
                            && coupon.destination_fee_policy == self.configuration.fee_policy
                            && coupon.family == f.family.id
                            && coupon.index == index as u32
                            && coupon.source == f.family.source
                            && coupon.destination == self.domain
                            && coupon.source != coupon.destination
                            && coupon.kind <= 1
                            && coupon.proof == currency.proof,
                        "family leaf identity/profile"
                    );
                    coupon.source_fee_policy.validate()?;
                    coupon.destination_fee_policy.validate()?;
                    ensure!(
                        coupon.fees.minimum_service >= coupon.source_fee_policy.minimum_service
                            && coupon.fees.minimum_archive
                                >= coupon.source_fee_policy.minimum_archive
                            && coupon.fees.minimum_work_author
                                >= coupon.source_fee_policy.minimum_work_author,
                        "coupon fee minima below sponsor profile"
                    );
                    coupon.limits.validate()?;
                    coupon.recipient.validate()?;
                    validate_use_policy(&coupon.use_policy)?;
                    coupon.close_policy.validate()?;
                    if coupon.kind == 1 {
                        validate_use_policy(&coupon.cancel_policy)?;
                        validate_use_policy(&coupon.recovery_policy)?;
                    } else {
                        coupon.cancel_policy.validate()?;
                        coupon.recovery_policy.validate()?;
                    }
                    ensure!(
                        coupon.source_family.family == coupon.source
                            && coupon.covers.len() <= 64
                            && !coupon.covers.is_empty()
                            && sorted_unique(&coupon.covers)
                            && coupon.max_slots <= 256,
                        "family leaf limits"
                    );
                    for cover_id in &coupon.covers {
                        let cover = f
                            .covers
                            .iter()
                            .find(|v| v.id(self.currency) == *cover_id)
                            .ok_or_else(|| anyhow::anyhow!("family missing accepted cover"))?;
                        self.configuration.accepts(cover)?;
                        ensure!(
                            cover.families.iter().any(|r| r == &coupon.source_family),
                            "source family differs from cover"
                        );
                    }
                    leaves.push(Entry {
                        key: hash("RLD-COUPON-INDEX", self.currency, &coupon.index),
                        value: coupon.digest(self.currency),
                    });
                }
                leaves.sort_by_key(|e| e.key);
                ensure!(
                    merkle::root(self.currency, &format!("{}/coupons", f.family.id), &leaves)?
                        == f.family.leaf_root,
                    "family leaf root"
                );
                let fam = &f.family;
                ensure!(
                    fam.destination == self.domain
                        && fam.id
                            == hash(
                                "RLD-COUPON-FAMILY-ID",
                                self.currency,
                                &(fam.source, fam.destination, fam.nonce, &fam.issuer)
                            )
                        && fam.count > 0
                        && fam.count <= 4096
                        && fam.units >= fam.count as u64
                        && self.families.get(fam.id).is_none()
                        && !self.used_funding.contains(&fam.funding, self.currency)?,
                    "new capability family"
                );
                crypto::authorize(&fam.issuer, &op.authorizations, &op.signing_bytes())?;
                verifier.native(&f.funding.source)?;
                let service = &f.funding.service;
                verifier.witness(
                    &f.funding.source.header,
                    "services",
                    service.id,
                    hash("RLD-SERVICE", self.currency, service),
                    &f.funding.inclusion,
                )?;
                ensure!(
                    fam.funding == service.id
                        && service.fee_policy == self.configuration.fee_policy.id(self.currency)
                        && service.beneficiary == self.domain
                        && service.family == fam.id
                        && service.capacity >= fam.units
                        && service.reserved >= fam.units
                        && sum(&service.balance)?.0 > 0,
                    "unfunded reservation"
                );
                self.used_funding.insert(fam.funding)?;
                self.families.insert(fam.clone())?;
            }
            Command::Handoff(h) => {
                crypto::identity_attestations(
                    &self.configuration,
                    &h.old_authorizations,
                    &tagged(
                        "RLD-HANDOFF-AUTHORIZATION",
                        self.currency,
                        &(self.configuration.id(), &h.next, committed_prestate),
                    ),
                )?;
                let next = &h.next;
                next.validate()?;
                ensure!(
                    next.limits == self.configuration.limits
                        && next.custody_profile == self.configuration.custody_profile
                        && next.succession == self.configuration.succession
                        && next.signature_profile == self.configuration.signature_profile,
                    "handoff cannot silently change original obligation profiles"
                );
                ensure!(
                    next.currency == self.currency
                        && next.domain == self.domain
                        && next.initial_anchor == self.configuration.initial_anchor
                        && next.epoch
                            == self
                                .configuration
                                .epoch
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("epoch exhaustion"))?
                        && next.first_sequence
                            == self
                                .sequence
                                .checked_add(1)
                                .ok_or_else(|| anyhow::anyhow!("sequence exhaustion"))?
                        && next.pool_epoch > self.configuration.pool_epoch,
                    "handoff identity/position"
                );
                crypto::identity_attestations(
                    next,
                    &h.new_acknowledgments,
                    &tagged(
                        "RLD-HANDOFF-ACK",
                        self.currency,
                        &(self.configuration.id(), next, committed_prestate),
                    ),
                )?;
                Verifier { currency }.admission(next, &h.admission)?;
                if !self.fee_policies.contains(&next.fee_policy) {
                    self.fee_policies.insert(next.fee_policy.clone())?;
                }
                self.configuration = next.clone();
                self.pool_next = 0;
            }
            Command::PayService {
                service,
                payouts,
                fees,
            } => {
                let mut contract = self
                    .services
                    .get(*service)
                    .ok_or_else(|| anyhow::anyhow!("service contract absent"))?
                    .clone();
                crypto::authorize(
                    &contract.custodians,
                    &op.authorizations,
                    &op.signing_bytes(),
                )?;
                ensure!(
                    !payouts.is_empty()
                        && payouts.len() + fees.len() <= 64
                        && payouts.iter().all(|a| a.owner == contract.custodians),
                    "contract service payout policy"
                );
                self.fees(currency, fees, &self.configuration.fee_policy)?;
                for a in payouts {
                    self.allocation(a)?;
                }
                let expenses: Vec<_> = payouts
                    .iter()
                    .map(|a| a.components.clone())
                    .chain(fees.iter().map(|f| f.payout.components.clone()))
                    .collect();
                let mut balance = totals([contract.balance.as_slice()])?;
                for (cover, n) in totals(expenses.iter().map(Vec::as_slice))? {
                    let previous = balance
                        .get(&cover)
                        .copied()
                        .ok_or_else(|| anyhow::anyhow!("service fee cover"))?;
                    let rest = previous.sub(n)?;
                    if rest.0 == 0 {
                        balance.remove(&cover);
                    } else {
                        balance.insert(cover, rest);
                    }
                }
                contract.balance = balance
                    .into_iter()
                    .map(|(cover, amount)| Component { cover, amount })
                    .collect();
                self.services.replace(contract)?;
                for a in payouts {
                    self.output(id, &mut index, a)?;
                }
                self.add_fees(id, &mut index, fees)?;
            }
            Command::Retire {
                inputs,
                change,
                retired,
            } => {
                let values = self.input_parts(inputs, op)?;
                self.usable(retired)?;
                let out: Vec<_> = change
                    .iter()
                    .map(|a| a.components.clone())
                    .chain(std::iter::once(retired.clone()))
                    .collect();
                self.conserve(&values, &out, &[])?;
                self.retired = self.retired.add(sum(retired)?)?;
                self.remove_inputs(inputs)?;
                for a in change {
                    self.output(id, &mut index, a)?;
                }
            }
            Command::ObserveExport(release) => {
                verifier.release(release)?;
                let c = &release.creation.controller;
                ensure!(
                    c.source == self.domain
                        && self.controllers.iter().any(|x| x == c)
                        && !self.redemptions.get(c.id)?.is_some_and(|r| r.kind == 1),
                    "export observation"
                );
                if self.resolutions.get(c.id)?.is_none() {
                    self.resolutions.insert(Decision {
                        object: c.id,
                        coupon: c.ticket.coupon,
                        outcome: 1,
                        digest: c.ticket.digest(self.currency),
                    })?;
                }
            }
            Command::ReportIncident { first, second } => {
                verifier.native(first)?;
                verifier.native(second)?;
                ensure!(
                    first.header.domain == second.header.domain
                        && first.header.sequence == second.header.sequence
                        && first.configuration == second.configuration
                        && first.header.id() != second.header.id(),
                    "not conflicting certificates"
                );
                if !self.incidents.iter().any(|i| {
                    i.family == first.header.domain
                        && i.anchor == first.configuration.initial_anchor
                }) {
                    self.incidents.insert(Incident {
                        family: first.header.domain,
                        anchor: first.configuration.initial_anchor,
                        first: Blob(encode(first)),
                        second: Blob(encode(second)),
                    })?;
                }
            }
        }
        self.applied.insert(Applied { id, digest })?;
        Ok(())
    }
    fn prepare(
        &mut self,
        currency: &Currency,
        op: &Operation,
        t: &Ticket,
        e: &CouponEvidence,
        keys: &[KeyLeaf],
        material: &Blob,
        claim: Option<&PlacementWork>,
        index: &mut u32,
    ) -> Result<()> {
        let v = Verifier { currency };
        v.coupon(e)?;
        let coupon = &e.coupon;
        let p = coupon.id(self.currency);
        ensure!(
            t.id == t.identity(self.currency)
                && t.source == self.domain
                && t.coupon == p
                && t.destination == coupon.destination
                && coupon.source == self.domain
                && coupon.source_family.family == self.domain
                && coupon.source_family.anchor == self.configuration.initial_anchor
                && coupon
                    .source_family
                    .succession
                    .contains(&self.configuration.succession)
                && coupon
                    .source_family
                    .signatures
                    .contains(&self.configuration.signature_profile)
                && coupon.source_family.custody == self.configuration.custody_profile
                && t.kind == coupon.kind
                && t.recipient.owner == coupon.recipient
                && t.cancel_policy == bound_claim_policy(&coupon.cancel_policy, &t.creator, t.kind)
                && t.recovery_policy
                    == bound_claim_policy(&coupon.recovery_policy, &t.creator, t.kind)
                && t.cancel_fee <= coupon.fees.cancel_max
                && t.recovery_fee <= coupon.fees.recovery_max,
            "prepared signed terms"
        );
        ensure!(
            self.coupon_uses.get(p).is_none()
                && self.controllers.get(t.id).is_none()
                && self.pool_next < crate::KEY_COUNT,
            "used coupon/controller/pool"
        );
        let mut outstanding = 0usize;
        for x in self.controllers.iter() {
            if self.resolutions.get(x.id)?.is_none() && self.redemptions.get(x.id)?.is_none() {
                outstanding = outstanding
                    .checked_add(1)
                    .context("controller count exhaustion")?;
            }
        }
        ensure!(
            outstanding < self.configuration.limits.controllers as usize,
            "outstanding-controller capacity"
        );
        let sponsor = self
            .services
            .get(coupon.source_sponsor)
            .ok_or_else(|| anyhow::anyhow!("source sponsor not retained"))?;
        ensure!(
            sponsor.family == coupon.family
                && sponsor.beneficiary == self.domain
                && sponsor.fee_policy == coupon.source_fee_policy.id(self.currency)
                && self.fee_policies.contains(&coupon.source_fee_policy)
                && sponsor.capacity >= e.family.count as u64
                && sponsor.reserved >= e.family.count as u64
                && sum(&sponsor.balance)?.0 > 0,
            "source controller service capacity unavailable"
        );
        crypto::authorize(&t.creator, &op.authorizations, &op.signing_bytes())?;
        crypto::authorize_use(&coupon.use_policy, &op.authorizations, &op.signing_bytes())?;
        ensure!(
            material.0.len() <= coupon.limits.capsule_bytes as usize,
            "prepared material size"
        );
        let m: Material = crate::codec::decode(&material.0, coupon.limits.capsule_bytes as usize)?;
        ensure!(
            m.ticket == *t
                && m.coupon == *coupon
                && m.outputs
                    == if claim.is_some() {
                        vec![]
                    } else {
                        vec![t.recipient.clone(), t.destination_fee.clone()]
                    },
            "material signed terms"
        );
        for cover in &m.covers {
            ensure!(
                self.cover(cover.id(self.currency))? == cover,
                "material cover definition"
            );
        }
        ensure!(
            t.inputs.len() <= coupon.limits.inputs as usize
                && t.change.len() + t.fees.len() + 2 <= coupon.limits.outputs as usize
                && t.recipient.components.len() <= coupon.limits.components as usize
                && t.destination_fee.components.len() <= coupon.limits.components as usize,
            "original preparation object bounds"
        );
        let escrow = if let Some(w) = claim {
            ensure!(
                t.inputs.is_empty()
                    && t.change.is_empty()
                    && t.fees.is_empty()
                    && t.lifts.is_empty()
                    && t.recipient.components.is_empty()
                    && t.destination_fee.components.is_empty()
                    && t.cancel_fee.0 == 0
                    && t.recovery_fee.0 == 0,
                "issuance is not a monetary payment"
            );
            let range = &w.range;
            ensure!(
                range.lo < range.hi
                    && range.hi - range.lo <= coupon.max_slots
                    && coupon.roots.contains(&range.root)
                    && coupon.covers.contains(&range.cover),
                "issuance coupon range"
            );
            let grant = self
                .grants
                .get(range.grant)
                .ok_or_else(|| anyhow::anyhow!("placement grant"))?
                .clone();
            ensure!(
                grant.root == range.root && grant.home == self.domain,
                "placement source"
            );
            self.cover(grant.cover)?
                .subset_of(self.cover(range.cover)?)?;
            let old = self
                .segments
                .before_or_at(Key::Segment(range.grant, range.lo))
                .filter(|s| s.grant == range.grant && s.cursor <= range.lo && range.hi <= s.hi)
                .ok_or_else(|| anyhow::anyhow!("selected slots consumed/delegated"))?
                .clone();
            self.segments
                .remove_key(Key::Segment(old.grant, old.cursor))?
                .context("placement segment absent")?;
            if old.cursor < range.lo {
                self.segments.insert(Segment {
                    hi: range.lo,
                    ..old.clone()
                })?;
            }
            if range.hi < old.hi {
                self.segments.insert(Segment {
                    grant: old.grant,
                    lo: range.hi,
                    hi: old.hi,
                    cursor: range.hi,
                    mint_anchor: hash(
                        "RLD-SEGMENT-OPEN",
                        self.currency,
                        &(old.grant, range.hi, op.id(), "split-right"),
                    ),
                })?;
            }
            Vec::new()
        } else {
            ensure!(
                t.range.is_none() && t.change.len() + t.fees.len() <= 64,
                "payment preparation count"
            );
            self.allocation(&t.recipient)?;
            self.allocation(&t.destination_fee)?;
            self.fees(currency, &t.fees, &coupon.source_fee_policy)?;
            let amounts = [0u8, 1, 2]
                .map(|kind| {
                    t.fees
                        .iter()
                        .filter(|f| f.kind == kind)
                        .try_fold(Amount(0), |a, f| a.add(sum(&f.payout.components)?))
                })
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                amounts[0] >= coupon.fees.minimum_service
                    && amounts[1] >= coupon.fees.minimum_work_author
                    && amounts[2] >= coupon.fees.minimum_archive,
                "coupon signed fee minima"
            );
            ensure!(
                t.destination_fee.owner == coupon.destination_fee_policy.service_owner
                    && sum(&t.destination_fee.components)?
                        >= coupon.destination_fee_policy.minimum_service,
                "destination service fee"
            );
            let amount = sum(&t.recipient.components)?.add(sum(&t.destination_fee.components)?)?;
            ensure!(
                sum(&t.recipient.components)? <= coupon.max_amount && amount.0 > 0,
                "coupon principal"
            );
            let values = self.input_parts(&t.inputs, op)?;
            let mut outputs: Vec<_> = t
                .change
                .iter()
                .map(|a| a.components.clone())
                .chain(t.fees.iter().map(|f| f.payout.components.clone()))
                .collect();
            outputs.push(t.recipient.components.clone());
            outputs.push(t.destination_fee.components.clone());
            self.conserve(&values, &outputs, &t.lifts)?;
            let esc = totals([
                t.recipient.components.as_slice(),
                t.destination_fee.components.as_slice(),
            ])?;
            ensure!(esc.len() <= 64, "escrow components");
            self.remove_inputs(&t.inputs)?;
            for a in &t.change {
                self.output(op.id(), index, a)?;
            }
            self.add_fees(op.id(), index, &t.fees)?;
            esc.into_iter()
                .map(|(cover, amount)| Component { cover, amount })
                .collect()
        };
        let controller = Controller {
            id: t.id,
            source: self.domain,
            ticket: t.clone(),
            coupon: coupon.clone(),
            configuration: self.configuration.clone(),
            pool_index: self.pool_next,
            keys: keys.to_vec(),
            escrow,
            material_root: Id::digest(&material.0),
            limits: coupon.limits.clone(),
        };
        proof::validate_controller(&controller)?;
        validate_ticket_covers(&controller, &m.covers)?;
        self.pool_next = self
            .pool_next
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("pool exhaustion"))?;
        self.controllers.insert(controller)?;
        self.births.insert(Birth {
            controller: t.id,
            sequence: self.sequence,
        })?;
        self.coupon_uses.insert(Delegation {
            coupon: p,
            controller: Some(t.id),
            closed: false,
        })?;
        Ok(())
    }
    fn redeem_cancel(
        &mut self,
        currency: &Currency,
        op: &Operation,
        p: &Cancellation,
        index: &mut u32,
    ) -> Result<()> {
        let c = self
            .controllers
            .get(p.controller)
            .ok_or_else(|| anyhow::anyhow!("unknown preparation"))?
            .clone();
        let birth = self
            .births
            .get(c.id)?
            .ok_or_else(|| anyhow::anyhow!("missing birth"))?;
        ensure!(
            self.redemptions.get(c.id)?.is_none()
                && !self.resolutions.get(c.id)?.is_some_and(|r| r.outcome == 1)
                && p.source_header.domain == self.domain
                && p.source_header.sequence == birth.sequence
                && p.source_header.configuration == c.configuration.id(),
            "cancel creation/redemption"
        );
        crypto::verify_quorum(
            &c.configuration,
            self.domain,
            None,
            &p.source_qc,
            3,
            p.source_header.id(),
        )?;
        ensure!(
            p.source_qc.votes[0].sequence == birth.sequence,
            "birth sequence QC"
        );
        let v = Verifier { currency };
        v.witness(
            &p.source_header,
            "controllers",
            c.id,
            hash("RLD-CONTROLLER", self.currency, &c),
            &p.delegation,
        )?;
        let d = Delegation {
            coupon: c.ticket.coupon,
            controller: Some(c.id),
            closed: false,
        };
        v.witness(
            &p.source_header,
            "coupon_uses",
            d.coupon,
            hash("RLD-DELEGATION", self.currency, &d),
            &p.coupon_use,
        )?;
        proof::validate_terminal(&c, p.source_header.id(), &p.terminal, 2)?;
        crypto::verify_quorum(
            &c.configuration,
            c.id,
            Some(c.pool_index),
            &p.qc,
            3,
            p.terminal.id(),
        )?;
        crypto::authorize(
            &c.ticket.cancel_policy,
            std::slice::from_ref(&p.authorization),
            &proof::cancellation_bytes(&c),
        )?;
        self.return_object(
            &c,
            c.ticket.cancel_fee,
            &c.ticket.cancel_fee_payout,
            op.id(),
            index,
        )?;
        self.redemptions.insert(Redemption {
            controller: c.id,
            kind: 1,
            operation: op.id(),
        })?;
        self.resolutions.insert(Decision {
            object: c.id,
            coupon: c.ticket.coupon,
            outcome: 2,
            digest: c.ticket.digest(self.currency),
        })?;
        let mut d = self
            .coupon_uses
            .get(c.ticket.coupon)
            .ok_or_else(|| anyhow::anyhow!("coupon use missing"))?
            .clone();
        d.closed = true;
        self.coupon_uses.replace(d)?;
        Ok(())
    }
    fn return_object(
        &mut self,
        c: &Controller,
        fee: Amount,
        fee_owner: &Owner,
        op: Id,
        index: &mut u32,
    ) -> Result<()> {
        if let Some(range) = &c.ticket.range {
            ensure!(fee.0 == 0, "issuance recovery fee");
            self.install(range, op)?;
        } else {
            let returned = remaining(&c.escrow, fee)?;
            if !returned.is_empty() {
                self.output(
                    op,
                    index,
                    &Allocation {
                        owner: c.ticket.recovery_policy.clone(),
                        components: returned,
                    },
                )?;
            }
            if fee.0 > 0 {
                let mut fee_parts = Vec::new();
                let mut n = fee;
                for p in &c.escrow {
                    let take = n.0.min(p.amount.0);
                    if take > 0 {
                        fee_parts.push(Component {
                            cover: p.cover,
                            amount: Amount(take),
                        });
                        n = n.sub(Amount(take))?;
                    }
                }
                let owner = fee_owner.clone();
                self.output(
                    op,
                    index,
                    &Allocation {
                        owner,
                        components: fee_parts,
                    },
                )?;
            }
        }
        Ok(())
    }
    fn install(&mut self, r: &Range, op: Id) -> Result<()> {
        ensure!(
            r.lo < r.hi && r.hi <= crate::SLOTS && r.root < crate::ROOTS,
            "installed slot bounds"
        );
        let creation = hash("RLD-GRANT-RELOCATE", self.currency, &(r, self.domain, op));
        let id = hash(
            "RLD-GRANT-ID",
            self.currency,
            &(r.root, r.lo, r.hi, self.domain, creation, r.cover),
        );
        ensure!(
            self.grants.get(id).is_none(),
            "duplicate grant installation"
        );
        self.grants.insert(Grant {
            id,
            root: r.root,
            lo: r.lo,
            hi: r.hi,
            home: self.domain,
            creation,
            cover: r.cover,
        })?;
        self.segments.insert(Segment {
            grant: id,
            lo: r.lo,
            hi: r.hi,
            cursor: r.lo,
            mint_anchor: hash(
                "RLD-SEGMENT-OPEN",
                self.currency,
                &(id, r.lo, creation, "installed"),
            ),
        })?;
        Ok(())
    }
    fn destination(
        &mut self,
        currency: &Currency,
        op: &Operation,
        r: &Release,
        reject: bool,
        index: &mut u32,
    ) -> Result<()> {
        let v = Verifier { currency };
        v.release(r)?;
        let c = &r.creation.controller;
        ensure!(
            c.ticket.destination == self.domain && c.coupon.destination == self.domain,
            "foreign destination"
        );
        let family = self
            .families
            .get(c.coupon.family)
            .ok_or_else(|| anyhow::anyhow!("receiving family absent"))?;
        ensure!(
            family.source == c.source && c.coupon.index < family.count,
            "reserved coupon"
        );
        if let Some(old) = self.decisions.get(c.id)? {
            ensure!(
                old.coupon == c.ticket.coupon
                    && old.digest == c.ticket.digest(self.currency)
                    && old.outcome == if reject { 2 } else { 1 },
                "conflicting terminal destination decision"
            );
            return Ok(());
        }
        ensure!(
            self.coupon_uses.get(c.ticket.coupon).is_none(),
            "destination coupon already consumed"
        );
        for cover in &r.covers {
            if !self.covers.contains(cover) {
                self.covers.insert(cover.clone())?;
            }
        }
        validate_ticket_covers(c, &r.covers)?;
        for cover_id in c
            .ticket
            .recipient
            .components
            .iter()
            .chain(&c.ticket.destination_fee.components)
            .map(|p| p.cover)
            .chain(c.ticket.range.iter().map(|r| r.cover))
        {
            self.configuration.accepts(self.cover(cover_id)?)?;
        }
        if !reject {
            for fee in &c.ticket.fees {
                if fee.kind == 1 {
                    self.remember_mint(
                        &fee.mint
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("released fee omitted Mint fact"))?
                            .record,
                    )?;
                }
            }
        }
        if reject {
            crypto::authorize(
                &c.ticket.recovery_policy,
                &op.authorizations,
                &op.signing_bytes(),
            )
            .or_else(|_| {
                crypto::authorize(&c.coupon.recipient, &op.authorizations, &op.signing_bytes())
            })?;
        } else if let Some(range) = &c.ticket.range {
            self.configuration.accepts(self.cover(range.cover)?)?;
            self.install(range, op.id())?;
        } else {
            self.output(op.id(), index, &c.ticket.recipient)?;
            self.output(op.id(), index, &c.ticket.destination_fee)?;
        }
        self.decisions.insert(Decision {
            object: c.id,
            coupon: c.ticket.coupon,
            outcome: if reject { 2 } else { 1 },
            digest: c.ticket.digest(self.currency),
        })?;
        self.coupon_uses.insert(Delegation {
            coupon: c.ticket.coupon,
            controller: Some(c.id),
            closed: true,
        })?;
        Ok(())
    }
}
pub fn validate_ticket_covers(c: &Controller, covers: &[Cover]) -> Result<()> {
    ensure!(
        covers.len() <= 64
            && covers
                .windows(2)
                .all(|w| w[0].id(c.configuration.currency) < w[1].id(c.configuration.currency)),
        "current cover order/count"
    );
    for cover in covers {
        cover.validate()?;
    }
    let ids: Vec<Id> = if let Some(r) = &c.ticket.range {
        vec![r.cover]
    } else {
        c.ticket
            .recipient
            .components
            .iter()
            .chain(&c.ticket.destination_fee.components)
            .map(|p| p.cover)
            .collect()
    };
    for id in ids {
        ensure!(
            c.coupon.covers.contains(&id),
            "coupon does not accept cover"
        );
        let cover = covers
            .iter()
            .find(|v| v.id(c.configuration.currency) == id)
            .ok_or_else(|| anyhow::anyhow!("missing current cover"))?;
        c.configuration.accepts(cover)?;
        ensure!(
            cover
                .families
                .iter()
                .any(|f| f.family == c.ticket.destination),
            "destination family not in signed cover"
        );
    }
    Ok(())
}
