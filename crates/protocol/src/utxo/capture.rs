use super::*;
use crate::{
    permanent::{
        access::AccessStep,
        capture::{Budget, Capture, CaptureBudgetExceeded, Log},
    },
    table::Record,
};
use std::{collections::BTreeMap, sync::Mutex};
struct Recording {
    inner: Outputs,
    trace: Capture<Output>,
    budget: Budget,
}
impl std::fmt::Debug for Recording {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputCapture")
            .field("count", &self.inner.len())
            .finish()
    }
}
impl Recording {
    fn record(&self, key: Id) -> Result<AccessStep<Output>> {
        let (member, absence) = self.inner.access(key)?;
        let step = AccessStep {
            root: self.root(),
            count: self.count(),
            key,
            value: self.inner.get(key)?,
            member,
            absence,
        };
        let mut log = self
            .trace
            .log
            .lock()
            .map_err(|_| anyhow::anyhow!("UTXO capture unavailable"))?;
        if let Some(i) = log.index.get(&(step.root, key)) {
            ensure!(log.steps[*i] == step, "changed UTXO captured evidence");
            return Ok(step);
        }
        if log.steps.len() >= 2_000_000 {
            return Err(CaptureBudgetExceeded.into());
        }
        self.budget.charge(&step)?;
        let i = log.steps.len();
        log.index.insert((step.root, key), i);
        log.steps.push(step.clone());
        Ok(step)
    }
    fn with(&self, inner: Outputs) -> Self {
        Self {
            inner,
            trace: self.trace.clone(),
            budget: self.budget.clone(),
        }
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
            .commitment(self.currency(), &self.inner.tag())
            .expect("fixed UTXO capture context")
    }
    fn count(&self) -> u64 {
        self.inner.len()
    }
    fn get(&self, key: Id) -> Result<Option<Output>> {
        Ok(self.record(key)?.value)
    }
    fn insert(&self, value: Output) -> Result<Arc<dyn Storage>> {
        let step = self.record(value.id)?;
        ensure!(step.value.is_none(), "duplicate captured UTXO");
        let expected = crate::merkle::insert_absent(
            self.currency(),
            &self.inner.tag(),
            self.root(),
            &value.entry(self.currency()),
            step.absence
                .as_ref()
                .context("UTXO capture insertion absence")?,
        )?;
        let mut inner = self.inner.clone();
        inner.insert(value)?;
        ensure!(
            inner.commitment(self.currency(), &inner.tag())? == expected,
            "captured UTXO insertion root"
        );
        Ok(Arc::new(self.with(inner)))
    }
    fn spend(&self, key: Id) -> Result<(Arc<dyn Storage>, Option<Output>)> {
        let step = self.record(key)?;
        if step.value.is_none() {
            return Ok((Arc::new(self.with(self.inner.clone())), None));
        }
        let expected = crate::merkle::remove_member(
            self.currency(),
            &self.inner.tag(),
            self.root(),
            step.member.as_ref().context("captured UTXO spend member")?,
        )?;
        let mut inner = self.inner.clone();
        let value = inner.remove(key)?;
        ensure!(
            value == step.value && inner.commitment(self.currency(), &inner.tag())? == expected,
            "captured UTXO spend root/value"
        );
        Ok((Arc::new(self.with(inner)), value))
    }
    fn access(&self, _: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        anyhow::bail!("UTXO capture cannot issue arbitrary membership")
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<Output>> + Send + '_> {
        Box::new(std::iter::once(Err(anyhow::anyhow!(
            "UTXO capture cannot export complete records"
        ))))
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
        let mut inner = self.inner.clone();
        inner.seal()?;
        Ok(Arc::new(self.with(inner)))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        anyhow::bail!("UTXO capture cannot become historical authority")
    }
    fn historical(&self, _: &[u8]) -> Result<Arc<dyn Storage>> {
        anyhow::bail!("UTXO capture cannot adopt historical authority")
    }
    fn empty(&self) -> Arc<dyn Storage> {
        Arc::new(self.with(Outputs::new(self.currency(), self.home())))
    }
}
impl Outputs {
    pub fn capture(self, budget: Budget) -> Result<(Self, Capture<Output>)> {
        ensure!(self.is_complete(), "UTXO capture complete map");
        let root = self.commitment(self.currency, &self.tag())?;
        let count = self.len();
        let opening = if count > 0 {
            let (m, a) = self.access(Id::ZERO)?;
            Some(
                m.or_else(|| a.and_then(|a| a.right.or(a.left)))
                    .context("UTXO capture opening")?,
            )
        } else {
            None
        };
        let trace = Capture {
            root,
            count,
            opening,
            log: Arc::new(Mutex::new(Log {
                steps: vec![],
                index: BTreeMap::new(),
            })),
        };
        let captured = Self {
            currency: self.currency,
            home: self.home,
            backing: Backing::Stored(Arc::new(Recording {
                inner: self,
                trace: trace.clone(),
                budget,
            })),
        };
        Ok((captured, trace))
    }
}
