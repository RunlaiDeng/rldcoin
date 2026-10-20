//! UTXO operations over the shared immutable typed path engine.
use crate::typed_paths::Paths;
use anyhow::Result;
use rld_protocol::{
    codec::Id,
    merkle::{Absence, Membership},
    model::Output,
    utxo::Storage,
};
use std::sync::Arc;
pub(crate) type Utxos = Paths<Output>;
impl Storage for Utxos {
    fn currency(&self) -> Id {
        Paths::currency(self)
    }
    fn home(&self) -> Id {
        Paths::home(self)
    }
    fn root(&self) -> Id {
        Paths::root(self)
    }
    fn count(&self) -> u64 {
        Paths::count(self)
    }
    fn get(&self, key: Id) -> Result<Option<Output>> {
        Paths::get(self, key)
    }
    fn insert(&self, value: Output) -> Result<Arc<dyn Storage>> {
        Ok(self.insert_path(value)?)
    }
    fn spend(&self, key: Id) -> Result<(Arc<dyn Storage>, Option<Output>)> {
        let (s, v) = self.spend_path(key)?;
        Ok((s, v))
    }
    fn access(&self, key: Id) -> Result<(Option<Membership>, Option<Absence>)> {
        Paths::access(self, key)
    }
    fn records(&self) -> Box<dyn Iterator<Item = Result<Output>> + Send + '_> {
        Paths::records(self)
    }
    fn seal(&self) -> Result<Arc<dyn Storage>> {
        Ok(self.seal_path()?)
    }
    fn snapshot(&self) -> Result<Vec<u8>> {
        Paths::snapshot(self)
    }
    fn historical(&self, b: &[u8]) -> Result<Arc<dyn Storage>> {
        Ok(self.historical_path(b)?)
    }
    fn empty(&self) -> Arc<dyn Storage> {
        self.empty_path()
    }
}
