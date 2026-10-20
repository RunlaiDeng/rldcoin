//! Private observations reconstructed from complete verified native execution.
use crate::{object_store::Objects, permanent_store::DiskPermanent, runtime::Initial};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Id, encode},
    model::*,
    permanent::Permanent,
    state::State,
};
use std::path::Path;
pub(crate) const DISK_MAPS: &[&str] = &[
    "services",
    "coupon_uses",
    "families",
    "covers",
    "fee_policies",
    "mints",
    "outputs",
    "applied",
    "births",
    "decisions",
    "redemptions",
    "resolutions",
    "funding",
];
#[derive(Clone)]
pub(crate) struct Backings {
    services: rld_protocol::mutable::Mutable<Service>,
    coupon_uses: rld_protocol::mutable::Mutable<Delegation>,
    families: Permanent<Family>,
    covers: Permanent<Cover>,
    fee_policies: Permanent<FeePolicy>,
    mints: rld_protocol::mints::Mints,
    outputs: rld_protocol::utxo::Outputs,
    applied: rld_protocol::applied::AppliedIndex,
    births: Permanent<Birth>,
    decisions: Permanent<Decision>,
    redemptions: Permanent<Redemption>,
    resolutions: Permanent<Decision>,
    funding: Permanent<Id>,
}
impl Backings {
    pub(crate) fn initialize(
        root: &Path,
        initial: &Initial,
        state: &mut State,
    ) -> Result<(std::sync::Arc<Objects>, std::sync::Arc<Objects>)> {
        let c = initial.currency.id();
        let d = initial.genesis.configuration.domain;
        let g = rld_protocol::state::genesis_id(c, &initial.genesis);
        let objects = Objects::open(
            &root.join("permanent-index"),
            &encode(&("RLD-PERMANENT-DISK-1", c, d, g)),
        )?;
        state.births =
            state
                .births
                .clone()
                .on_empty_storage(std::sync::Arc::new(DiskPermanent::empty(
                    objects.clone(),
                    initial,
                    "births",
                )?))?;
        state.decisions = state
            .decisions
            .clone()
            .on_empty_storage(std::sync::Arc::new(DiskPermanent::empty(
                objects.clone(),
                initial,
                "decisions",
            )?))?;
        state.redemptions = state
            .redemptions
            .clone()
            .on_empty_storage(std::sync::Arc::new(DiskPermanent::empty(
                objects.clone(),
                initial,
                "redemptions",
            )?))?;
        state.resolutions = state
            .resolutions
            .clone()
            .on_empty_storage(std::sync::Arc::new(DiskPermanent::empty(
                objects.clone(),
                initial,
                "resolutions",
            )?))?;
        state.used_funding = state
            .used_funding
            .clone()
            .on_empty_storage(std::sync::Arc::new(DiskPermanent::empty(
                objects.clone(),
                initial,
                "funding",
            )?))?;
        let definitions = crate::definitions_store::initialize(root, initial, state)?;
        Ok((objects, definitions))
    }
    pub(crate) fn mint_claim(&self) -> Result<rld_protocol::mints::index::Claim> {
        self.mints.index_claim()
    }
    pub(crate) fn capture(s: &State) -> Self {
        Self {
            services: s.services.clone(),
            coupon_uses: s.coupon_uses.clone(),
            families: s.families.clone(),
            covers: s.covers.clone(),
            fee_policies: s.fee_policies.clone(),
            mints: s.mints.clone(),
            outputs: s.outputs.clone(),
            applied: s.applied.clone(),
            births: s.births.clone(),
            decisions: s.decisions.clone(),
            redemptions: s.redemptions.clone(),
            resolutions: s.resolutions.clone(),
            funding: s.used_funding.clone(),
        }
    }
    pub(crate) fn seal(s: &mut State) -> Result<()> {
        s.services.seal()?;
        s.coupon_uses.seal()?;
        s.families.seal()?;
        s.covers.seal()?;
        s.fee_policies.seal()?;
        s.mints.seal()?;
        s.outputs.seal()?;
        s.applied.seal_storage()?;
        s.births.seal()?;
        s.decisions.seal()?;
        s.redemptions.seal()?;
        s.resolutions.seal()?;
        s.used_funding.seal()?;
        Ok(())
    }
    pub(crate) fn snapshot(s: &State) -> Result<Vec<u8>> {
        let [events, slots] = crate::storage_observation::split_mints(&s.mints.snapshot()?)?;
        crate::storage_observation::pack([
            s.applied
                .storage_snapshot()?
                .context("applied disk observation")?,
            s.births.snapshot()?,
            s.decisions.snapshot()?,
            s.redemptions.snapshot()?,
            s.resolutions.snapshot()?,
            s.used_funding.snapshot()?,
            s.outputs.snapshot()?,
            events,
            slots,
            s.covers.snapshot()?,
            s.fee_policies.snapshot()?,
            s.services.snapshot()?,
            s.coupon_uses.snapshot()?,
            s.families.snapshot()?,
        ])
    }
    pub(crate) fn historical(&self, bytes: &[u8]) -> Result<Self> {
        let [
            applied,
            births,
            decisions,
            redemptions,
            resolutions,
            funding,
            outputs,
            events,
            slots,
            covers,
            fee_policies,
            services,
            coupon_uses,
            families,
        ] = crate::storage_observation::unpack(bytes)?;
        Ok(Self {
            services: self.services.historical(&services)?,
            coupon_uses: self.coupon_uses.historical(&coupon_uses)?,
            families: self.families.historical(&families)?,
            covers: self.covers.historical(&covers)?,
            fee_policies: self.fee_policies.historical(&fee_policies)?,
            mints: self
                .mints
                .historical(&crate::storage_observation::join_mints(events, slots))?,
            outputs: self.outputs.historical(&outputs)?,
            applied: self.applied.historical_storage(&applied)?,
            births: self.births.historical(&births)?,
            decisions: self.decisions.historical(&decisions)?,
            redemptions: self.redemptions.historical(&redemptions)?,
            resolutions: self.resolutions.historical(&resolutions)?,
            funding: self.funding.historical(&funding)?,
        })
    }
    pub(crate) fn empty(&self) -> Result<Self> {
        Ok(Self {
            services: self.services.empty_storage()?,
            coupon_uses: self.coupon_uses.empty_storage()?,
            families: self.families.empty_storage()?,
            covers: self.covers.empty_storage()?,
            fee_policies: self.fee_policies.empty_storage()?,
            mints: self.mints.empty_storage()?,
            outputs: self.outputs.empty_storage()?,
            applied: self.applied.empty_storage()?,
            births: self.births.empty_storage()?,
            decisions: self.decisions.empty_storage()?,
            redemptions: self.redemptions.empty_storage()?,
            resolutions: self.resolutions.empty_storage()?,
            funding: self.funding.empty_storage()?,
        })
    }
    pub(crate) fn query(
        s: &State,
        name: &str,
        key: Id,
    ) -> Result<
        Option<(
            Option<rld_protocol::merkle::Membership>,
            Option<rld_protocol::merkle::Absence>,
        )>,
    > {
        Ok(Some(match name {
            "services" => s.services.access(key)?,
            "coupon_uses" => s.coupon_uses.access(key)?,
            "families" => s.families.access(key)?,
            "covers" => s.covers.access(key)?,
            "fee_policies" => s.fee_policies.access(key)?,
            "mints" => s.mints.access(key)?,
            "outputs" => s.outputs.access(key)?,
            "applied" => {
                let step = s.applied.access_step(key)?;
                (step.member, step.absence)
            }
            "births" => s.births.access(key)?,
            "decisions" => s.decisions.access(key)?,
            "redemptions" => s.redemptions.access(key)?,
            "resolutions" => s.resolutions.access(key)?,
            "funding" => s.used_funding.access(key)?,
            _ => return Ok(None),
        }))
    }
    pub(crate) fn clear_material(s: &mut State) {
        Self::clear_permanent_material(s);
        Self::clear_definition_material(s);
        Self::clear_service_material(s);
        s.outputs = rld_protocol::utxo::Outputs::new(s.currency, s.domain);
        s.mints = rld_protocol::mints::Mints::new(s.currency, s.domain);
    }
    pub(crate) fn clear_service_material(s: &mut State) {
        s.services =
            rld_protocol::mutable::Mutable::new(s.currency, &format!("{}/services", s.domain));
        s.coupon_uses =
            rld_protocol::mutable::Mutable::new(s.currency, &format!("{}/coupon_uses", s.domain));
        s.families = Permanent::new(s.currency, &format!("{}/families", s.domain));
    }
    pub(crate) fn clear_definition_material(s: &mut State) {
        s.covers = Permanent::new(s.currency, &format!("{}/covers", s.domain));
        s.fee_policies = Permanent::new(s.currency, &format!("{}/fee_policies", s.domain));
    }
    pub(crate) fn attach_genesis(mut self, s: &mut State) -> Result<()> {
        let (covers, policies) =
            crate::definitions_store::seed_genesis(s, self.covers, self.fee_policies)?;
        self.covers = covers;
        self.fee_policies = policies;
        Self::clear_definition_material(s);
        self.attach(s)
    }
    pub(crate) fn clear_permanent_material(s: &mut State) {
        let c = s.currency;
        let d = s.domain;
        s.applied = rld_protocol::applied::AppliedIndex::new(c, &format!("{d}/applied"));
        s.births = Permanent::new(c, &format!("{d}/births"));
        s.decisions = Permanent::new(c, &format!("{d}/decisions"));
        s.redemptions = Permanent::new(c, &format!("{d}/redemptions"));
        s.resolutions = Permanent::new(c, &format!("{d}/resolutions"));
        s.used_funding = Permanent::new(c, &format!("{d}/funding"));
    }
    pub(crate) fn attach(&self, s: &mut State) -> Result<()> {
        ensure!(
            s.services.is_complete()
                && s.services.is_empty()
                && s.coupon_uses.is_complete()
                && s.coupon_uses.is_empty()
                && s.families.is_complete()
                && s.families.is_empty()
                && s.covers.is_complete()
                && s.covers.is_empty()
                && s.fee_policies.is_complete()
                && s.fee_policies.is_empty()
                && s.mints.is_complete()
                && s.mints.is_empty()
                && s.outputs.is_complete()
                && s.outputs.is_empty()
                && s.applied.is_empty()
                && s.births.is_empty()
                && s.decisions.is_empty()
                && s.redemptions.is_empty()
                && s.resolutions.is_empty()
                && s.used_funding.is_empty(),
            "disk material placeholders must be empty"
        );
        s.services = self.services.clone();
        s.coupon_uses = self.coupon_uses.clone();
        s.families = self.families.clone();
        s.covers = self.covers.clone();
        s.fee_policies = self.fee_policies.clone();
        s.mints = self.mints.clone();
        s.outputs = self.outputs.clone();
        s.applied = self.applied.clone();
        s.births = self.births.clone();
        s.decisions = self.decisions.clone();
        s.redemptions = self.redemptions.clone();
        s.resolutions = self.resolutions.clone();
        s.used_funding = self.funding.clone();
        Ok(())
    }
}
