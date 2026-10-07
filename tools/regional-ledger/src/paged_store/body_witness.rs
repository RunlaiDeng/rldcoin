//! Process-only identities and a commitment to this invocation's executed prefix.
//! Complete retained bytes may resolve evicted identities, never initialize state.
use super::*;
use std::collections::VecDeque;

pub(super) trait History {
    fn require_scope(&self, scope: &Scope) -> Result<()>;
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64>;
}
impl History for Stream<Record> {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        self.require_scope(scope)
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        self.visit(self.storage_head(), consumer)
    }
}

#[derive(Clone, Default)]
pub(super) struct Bodies {
    values: BTreeMap<Hash, Hash>,
    order: VecDeque<Hash>,
}
impl Bodies {
    pub(super) fn get(&self, sid: &Hash) -> Option<&Hash> {
        self.values.get(sid)
    }
    pub(super) fn remember(&mut self, sid: Hash, body: Hash) -> Result<()> {
        if let Some(old) = self.values.get(&sid) {
            return require(*old == body, "executed body identity differs");
        }
        if self.values.len() == MAX_COINS {
            let oldest = self.order.pop_front().ok_or("body witness order missing")?;
            require(
                self.values.remove(&oldest).is_some(),
                "body witness order differs",
            )?;
        }
        self.values.insert(sid, body);
        self.order.push_back(sid);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.values.len()
    }
}

#[derive(Clone)]
pub(super) struct ExecutedPrefix {
    pub(super) scope: Scope,
    count: u64,
    head: Hash,
}
impl ExecutedPrefix {
    pub(super) fn new(scope: Scope) -> Result<Self> {
        Ok(Self {
            head: scope.initial()?,
            scope,
            count: 0,
        })
    }
    // Called only AFTER successful complete Native execution, never on load.
    pub(super) fn advance(&mut self, record: &Record) -> Result<()> {
        let next = self
            .count
            .checked_add(1)
            .ok_or("executed prefix overflow")?;
        let head = crate::retained_pages::next_head(self.head, self.count, record)?;
        self.count = next;
        self.head = head;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn corrupt_head_for_fixture(&mut self) {
        self.head = Hash([9; 32]);
    }
    pub(super) fn find(&self, stream: &dyn History, sid: Hash) -> Result<Option<Hash>> {
        stream.require_scope(&self.scope)?;
        let mut count = 0u64;
        let mut head = self.scope.initial()?;
        let mut found = None;
        // Validate the WHOLE held current stream, but consult only the already
        // executed ordered prefix. Future bytes cannot claim prior execution.
        stream.visit(&mut |record| {
            if count < self.count {
                head = crate::retained_pages::next_head(head, count, record)?;
                count += 1;
                for snapshot in record.snapshots()? {
                    if snapshot.statement.id()? == sid {
                        let complete = body(&snapshot)?;
                        if let Some(old) = found {
                            require(old == complete, "executed prefix body differs")?;
                        }
                        found = Some(complete);
                    }
                }
            }
            Ok(())
        })?;
        require(
            count == self.count && head == self.head,
            "retained bytes differ from this invocation's executed prefix",
        )?;
        Ok(found)
    }
}
