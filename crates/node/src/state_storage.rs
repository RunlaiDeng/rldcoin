//! Private observations reconstructed from complete verified native execution.
use crate::{object_store::Objects, permanent_store::DiskPermanent, runtime::Initial};
use anyhow::{Context, Result, ensure};
use rld_protocol::{
    codec::{Blob, Id, decode, encode},
    model::*,
    permanent::Permanent,
    record,
    state::State,
};
use std::path::Path;
record!(Snapshot{format:String => 0,applied:Blob => 1,births:Blob => 2,decisions:Blob => 3,redemptions:Blob => 4,resolutions:Blob => 5,funding:Blob => 6});
const FORMAT: &str = "RLD-NATIVE-DISK-OBSERVATION-1";
pub(crate) const DISK_MAPS: &[&str] = &[
    "applied",
    "births",
    "decisions",
    "redemptions",
    "resolutions",
    "funding",
];
#[derive(Clone)]
pub(crate) struct Backings {
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
    ) -> Result<std::sync::Arc<Objects>> {
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
        Ok(objects)
    }
    pub(crate) fn capture(s: &State) -> Self {
        Self {
            applied: s.applied.clone(),
            births: s.births.clone(),
            decisions: s.decisions.clone(),
            redemptions: s.redemptions.clone(),
            resolutions: s.resolutions.clone(),
            funding: s.used_funding.clone(),
        }
    }
    pub(crate) fn seal(s: &mut State) -> Result<()> {
        s.applied.seal_storage()?;
        s.births.seal()?;
        s.decisions.seal()?;
        s.redemptions.seal()?;
        s.resolutions.seal()?;
        s.used_funding.seal()?;
        Ok(())
    }
    pub(crate) fn snapshot(s: &State) -> Result<Vec<u8>> {
        let bytes = encode(&Snapshot {
            format: FORMAT.into(),
            applied: Blob(
                s.applied
                    .storage_snapshot()?
                    .context("applied disk observation")?,
            ),
            births: Blob(s.births.snapshot()?),
            decisions: Blob(s.decisions.snapshot()?),
            redemptions: Blob(s.redemptions.snapshot()?),
            resolutions: Blob(s.resolutions.snapshot()?),
            funding: Blob(s.used_funding.snapshot()?),
        });
        ensure!(bytes.len() <= 4096, "native disk observation bound");
        Ok(bytes)
    }
    pub(crate) fn historical(&self, b: &[u8]) -> Result<Self> {
        let s: Snapshot = decode(b, 4096)?;
        ensure!(s.format == FORMAT, "native disk observation format");
        Ok(Self {
            applied: self.applied.historical_storage(&s.applied.0)?,
            births: self.births.historical(&s.births.0)?,
            decisions: self.decisions.historical(&s.decisions.0)?,
            redemptions: self.redemptions.historical(&s.redemptions.0)?,
            resolutions: self.resolutions.historical(&s.resolutions.0)?,
            funding: self.funding.historical(&s.funding.0)?,
        })
    }
    pub(crate) fn empty(&self) -> Result<Self> {
        Ok(Self {
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
            s.applied.is_empty()
                && s.births.is_empty()
                && s.decisions.is_empty()
                && s.redemptions.is_empty()
                && s.resolutions.is_empty()
                && s.used_funding.is_empty(),
            "disk material placeholders must be empty"
        );
        s.applied = self.applied.clone();
        s.births = self.births.clone();
        s.decisions = self.decisions.clone();
        s.redemptions = self.redemptions.clone();
        s.resolutions = self.resolutions.clone();
        s.used_funding = self.funding.clone();
        Ok(())
    }
}
