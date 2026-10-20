//! Host-only capture while replaying already verified native records. Every
//! access is still authenticated by the actual guest; this log grants no rights.
use super::{
    access::{Access, AccessStep, FORMAT},
    *,
};
use std::{collections::BTreeMap, sync::Mutex};
#[derive(Debug)]
pub struct CaptureBudgetExceeded;
impl std::fmt::Display for CaptureBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "permanent witness capture capacity exceeded")
    }
}
impl std::error::Error for CaptureBudgetExceeded {}
struct BudgetState {
    bytes: usize,
    limit: usize,
}
#[derive(Clone)]
pub struct Budget {
    state: Arc<Mutex<BudgetState>>,
}
impl Budget {
    pub fn new(limit: usize, framing: usize) -> Result<Self> {
        ensure!(framing <= limit, "capture framing budget");
        Ok(Self {
            state: Arc::new(Mutex::new(BudgetState {
                bytes: framing,
                limit,
            })),
        })
    }
    pub fn charge<T: Encode<()>>(&self, value: &T) -> Result<()> {
        struct Sink<'a> {
            state: &'a mut BudgetState,
            exceeded: bool,
        }
        impl minicbor::encode::Write for Sink<'_> {
            type Error = std::io::Error;
            fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
                if let Some(n) = self
                    .state
                    .bytes
                    .checked_add(b.len())
                    .filter(|n| *n <= self.state.limit)
                {
                    self.state.bytes = n;
                    Ok(())
                } else {
                    self.exceeded = true;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "capture byte capacity",
                    ))
                }
            }
        }
        let mut guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("capture budget unavailable"))?;
        let mut sink = Sink {
            state: &mut guard,
            exceeded: false,
        };
        let result = value.encode(&mut Encoder::new(&mut sink), &mut ());
        if sink.exceeded {
            return Err(CaptureBudgetExceeded.into());
        }
        result?;
        Ok(())
    }
}
pub(crate) struct Log<T> {
    pub(crate) steps: Vec<AccessStep<T>>,
    pub(crate) index: BTreeMap<(Id, Id), usize>,
}
#[derive(Clone)]
pub struct Capture<T> {
    pub(crate) root: Id,
    pub(crate) count: u64,
    pub(crate) opening: Option<Membership>,
    pub(crate) log: Arc<Mutex<Log<T>>>,
}
impl<T: Record> Capture<T> {
    pub fn finish(self) -> Result<Access<T>> {
        let log = Arc::try_unwrap(self.log)
            .map_err(|_| anyhow::anyhow!("capture still has live execution observations"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("capture log unavailable"))?;
        Ok(Access {
            format: FORMAT.into(),
            root: self.root,
            count: self.count,
            steps: log.steps,
            opening: self.opening,
        })
    }
    pub fn metadata(&self) -> Access<T> {
        Access {
            format: FORMAT.into(),
            root: self.root,
            count: self.count,
            steps: vec![],
            opening: self.opening.clone(),
        }
    }
}
struct Recording<T: Record> {
    inner: Permanent<T>,
    log: Arc<Mutex<Log<T>>>,
    budget: Budget,
    currency: Id,
    tag: String,
}
impl<T: Record + 'static> std::fmt::Debug for Recording<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recording")
            .field("tag", &self.tag)
            .field("count", &self.inner.len())
            .finish()
    }
}
impl<T: Record + Encode<()> + Send + Sync + 'static> Recording<T> {
    fn record(&self, key: Id) -> Result<AccessStep<T>> {
        let (member, absence) = self.inner.access(key)?;
        let value = self.inner.get(key)?;
        let step = AccessStep {
            root: self.inner.commitment(self.currency, &self.tag)?,
            count: self.inner.len(),
            key,
            value,
            member,
            absence,
        };
        let mut log = self
            .log
            .lock()
            .map_err(|_| anyhow::anyhow!("capture log unavailable"))?;
        if let Some(i) = log.index.get(&(step.root, key)) {
            ensure!(log.steps[*i] == step, "changed captured root/key evidence");
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
    fn with(&self, inner: Permanent<T>) -> Self {
        Self {
            inner,
            log: self.log.clone(),
            budget: self.budget.clone(),
            currency: self.currency,
            tag: self.tag.clone(),
        }
    }
}
impl<T: Record + Encode<()> + Send + Sync + 'static> Storage<T> for Recording<T> {
    fn currency(&self) -> Id {
        self.currency
    }
    fn tag(&self) -> &str {
        &self.tag
    }
    fn root(&self) -> Id {
        self.inner
            .commitment(self.currency, &self.tag)
            .expect("fixed capture context")
    }
    fn count(&self) -> u64 {
        self.inner.len()
    }
    fn get(&self, key: Id) -> Result<Option<T>> {
        Ok(self.record(key)?.value)
    }
    fn insert(&self, value: T) -> Result<Arc<dyn Storage<T>>> {
        let e = value.entry(self.currency);
        ensure!(
            value.key(self.currency) == Key::Id(e.key),
            "captured direct record key"
        );
        let step = self.record(e.key)?;
        ensure!(step.value.is_none(), "duplicate captured insertion");
        let root = crate::merkle::insert_absent(
            self.currency,
            &self.tag,
            step.root,
            &e,
            step.absence
                .as_ref()
                .context("captured insertion absence")?,
        )?;
        let mut inner = self.inner.clone();
        inner.insert(value)?;
        ensure!(
            inner.commitment(self.currency, &self.tag)? == root,
            "captured/complete insertion root mismatch"
        );
        Ok(Arc::new(self.with(inner)))
    }
    fn access(&self, _: Id) -> Result<(Option<Membership>, Option<crate::merkle::Absence>)> {
        anyhow::bail!("capture cannot issue arbitrary membership")
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<T>> + Send + '_> {
        Box::new(std::iter::once(Err(anyhow::anyhow!(
            "capture cannot export complete records"
        ))))
    }
    fn seal(&self) -> Result<Arc<dyn Storage<T>>> {
        let mut inner = self.inner.clone();
        inner.seal()?;
        Ok(Arc::new(self.with(inner)))
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        anyhow::bail!("capture cannot become historical authority")
    }
    fn historical(&self, _: &[u8]) -> Result<Arc<dyn Storage<T>>> {
        anyhow::bail!("capture cannot adopt historical storage")
    }
    fn empty(&self) -> Arc<dyn Storage<T>> {
        Arc::new(self.with(Permanent::new(self.currency, &self.tag)))
    }
}
impl<T: Record + Encode<()> + Send + Sync + 'static> Permanent<T> {
    pub fn capture(self, c: Id, tag: &str, budget: Budget) -> Result<(Self, Capture<T>)> {
        ensure!(self.is_complete(), "capture requires complete map");
        let root = self.commitment(c, tag)?;
        let count = self.len();
        let opening = if count > 0 {
            let (member, absence) = self.access(Id::ZERO)?;
            Some(
                member
                    .or_else(|| absence.and_then(|a| a.right.or(a.left)))
                    .context("capture root opening")?,
            )
        } else {
            None
        };
        let log = Arc::new(Mutex::new(Log {
            steps: vec![],
            index: BTreeMap::new(),
        }));
        Ok((
            Self {
                backing: Backing::Stored(Arc::new(Recording {
                    inner: self,
                    log: log.clone(),
                    budget,
                    currency: c,
                    tag: tag.into(),
                })),
            },
            Capture {
                root,
                count,
                opening,
                log,
            },
        ))
    }
}
