//! Capture both append-only indexes from an already verified native replay.
//! The guest independently authenticates the correspondence and every access.
use super::*;
use crate::permanent::{
    access::AccessStep,
    capture::{Budget, Capture, CaptureBudgetExceeded, Log},
};
use std::{collections::BTreeMap, sync::Mutex};

pub struct MintCapture {
    events: Capture<MintRecord>,
    slots: Capture<Slot>,
}
impl MintCapture {
    pub fn finish(self, certificate: index::Certificate) -> Result<IndexedAccess> {
        Ok(IndexedAccess {
            certificate,
            events: self.events.finish()?,
            slots: self.slots.finish()?,
        })
    }
    pub fn metadata(&self, certificate: index::Certificate) -> IndexedAccess {
        IndexedAccess {
            certificate,
            events: self.events.metadata(),
            slots: self.slots.metadata(),
        }
    }
}
struct Recording {
    inner: Mints,
    events: Capture<MintRecord>,
    slots: Capture<Slot>,
    budget: Budget,
}
impl std::fmt::Debug for Recording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintCapture")
            .field("count", &self.inner.len())
            .finish()
    }
}
impl Recording {
    fn with(&self, inner: Mints) -> Self {
        Self {
            inner,
            events: self.events.clone(),
            slots: self.slots.clone(),
            budget: self.budget.clone(),
        }
    }
    fn retain<T: crate::table::Record + minicbor::Encode<()>>(
        &self,
        trace: &Capture<T>,
        step: AccessStep<T>,
    ) -> Result<AccessStep<T>> {
        let mut log = trace
            .log
            .lock()
            .map_err(|_| anyhow::anyhow!("Mint capture log unavailable"))?;
        if let Some(i) = log.index.get(&(step.root, step.key)) {
            ensure!(
                log.steps[*i] == step,
                "changed Mint captured root/key evidence"
            );
            return Ok(step);
        }
        if log.steps.len() >= 2_000_000 {
            return Err(CaptureBudgetExceeded.into());
        }
        self.budget.charge(&step)?;
        let i = log.steps.len();
        log.index.insert((step.root, step.key), i);
        log.steps.push(step.clone());
        Ok(step)
    }
    fn event(&self, key: Id) -> Result<AccessStep<MintRecord>> {
        let (member, absence) = self.inner.access(key)?;
        self.retain(
            &self.events,
            AccessStep {
                root: self.inner.index_claim()?.events,
                count: self.inner.len(),
                key,
                value: self.inner.get(key)?,
                member,
                absence,
            },
        )
    }
    fn slot(&self, key: Id) -> Result<AccessStep<Slot>> {
        let (member, absence) = self.inner.slot_access(key)?;
        let value = member
            .as_ref()
            .map(|m| Slot::from_entry(&m.entry))
            .transpose()?;
        self.retain(
            &self.slots,
            AccessStep {
                root: self.inner.index_claim()?.slots,
                count: self.inner.len(),
                key,
                value,
                member,
                absence,
            },
        )
    }
}
impl Storage for Recording {
    fn currency(&self) -> Id {
        self.inner.currency
    }
    fn home(&self) -> Id {
        self.inner.home
    }
    fn root(&self) -> Id {
        self.inner
            .index_claim()
            .expect("fixed Mint capture context")
            .events
    }
    fn count(&self) -> u64 {
        self.inner.len()
    }
    fn slot_root(&self) -> Id {
        self.inner
            .index_claim()
            .expect("fixed Mint capture context")
            .slots
    }
    fn slot_access(&self, _: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        anyhow::bail!("Mint capture cannot issue arbitrary slot access")
    }
    fn get(&self, key: Id) -> Result<Option<MintRecord>> {
        Ok(self.event(key)?.value)
    }
    fn slot_before_or_at(&self, key: Id) -> Result<Option<MintRecord>> {
        let step = self.slot(key)?;
        let entry = step.member.as_ref().map(|m| &m.entry).or_else(|| {
            step.absence
                .as_ref()
                .and_then(|a| a.left.as_ref().map(|m| &m.entry))
        });
        let value = entry
            .map(|entry| {
                let s = Slot::from_entry(entry)?;
                let v = self
                    .event(s.event)?
                    .value
                    .context("captured Mint slot has no event")?;
                ensure!(
                    v.root == s.root && v.slot == s.slot && v.event == s.event,
                    "captured Mint slot/event mismatch"
                );
                Ok(v)
            })
            .transpose()?;
        ensure!(
            value == self.inner.before_or_at(key)?,
            "captured Mint predecessor differs from complete index"
        );
        Ok(value)
    }
    fn insert(&self, value: MintRecord) -> Result<Arc<dyn Storage>> {
        let c = self.currency();
        let d = self.home();
        let e = self.event(value.event)?;
        let slot = Slot {
            root: value.root,
            slot: value.slot,
            event: value.event,
        };
        let s = self.slot(slot_key(value.root, value.slot))?;
        ensure!(
            e.value.is_none() && s.value.is_none(),
            "duplicate captured Mint event/slot"
        );
        let events = crate::merkle::insert_absent(
            c,
            &format!("{d}/mints"),
            e.root,
            &value.entry(c),
            e.absence.as_ref().context("captured Mint event absence")?,
        )?;
        let slots = crate::merkle::insert_absent(
            c,
            &format!("{d}/mint-slots-aux"),
            s.root,
            &slot.entry(c),
            s.absence.as_ref().context("captured Mint slot absence")?,
        )?;
        let mut inner = self.inner.clone();
        inner.insert(value)?;
        let claim = inner.index_claim()?;
        ensure!(
            claim.events == events && claim.slots == slots,
            "captured/complete Mint roots differ"
        );
        Ok(Arc::new(self.with(inner)))
    }
    fn access(&self, _: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        anyhow::bail!("Mint capture cannot issue arbitrary event access")
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<MintRecord>> + Send + '_> {
        Box::new(std::iter::once(Err(anyhow::anyhow!(
            "Mint capture cannot export complete records"
        ))))
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
        let mut inner = self.inner.clone();
        inner.seal()?;
        Ok(Arc::new(self.with(inner)))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        anyhow::bail!("Mint capture cannot become history authority")
    }
    fn historical(&self, _: &[u8]) -> Result<Arc<dyn Storage>> {
        anyhow::bail!("Mint capture cannot adopt history")
    }
    fn empty(&self) -> Arc<dyn Storage> {
        Arc::new(self.with(Mints::new(self.currency(), self.home())))
    }
}
fn trace<T: crate::table::Record>(
    root: Id,
    count: u64,
    member: Option<Membership>,
    absence: Option<Absence>,
) -> Result<Capture<T>> {
    let opening = if count == 0 {
        None
    } else {
        Some(
            member
                .or_else(|| absence.and_then(|a| a.right.or(a.left)))
                .context("Mint capture root/count opening")?,
        )
    };
    Ok(Capture {
        root,
        count,
        opening,
        log: Arc::new(Mutex::new(Log {
            steps: vec![],
            index: BTreeMap::new(),
        })),
    })
}
impl Mints {
    pub fn capture(self, budget: Budget) -> Result<(Self, MintCapture)> {
        ensure!(self.is_complete(), "Mint capture requires complete maps");
        let claim = self.index_claim()?;
        let (m, a) = self.access(Id::ZERO)?;
        let events = trace(claim.events, claim.count, m, a)?;
        let (m, a) = self.slot_access(Id::ZERO)?;
        let slots = trace(claim.slots, claim.count, m, a)?;
        let c = self.currency;
        let d = self.home;
        Ok((
            Self {
                currency: c,
                home: d,
                backing: Backing::Stored(Arc::new(Recording {
                    inner: self,
                    events: events.clone(),
                    slots: slots.clone(),
                    budget,
                })),
            },
            MintCapture { events, slots },
        ))
    }
}
