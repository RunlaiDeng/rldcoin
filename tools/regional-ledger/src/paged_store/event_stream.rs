//! Ledger storage selection comes only from the verified signed admission.
//! Both representations reconstruct complete records; neither initializes state.
use super::*;
use crate::retained_pages::packed::live::AppendablePackedStreamCandidate as Packed;

pub(crate) enum EventStream {
    Flat(Stream<Record>),
    Packed(Packed<Record>),
}
impl EventStream {
    pub(crate) fn create(dir: &Path, scope: Scope, packed: bool) -> Result<Self> {
        if packed {
            Packed::create(dir, scope).map(Self::Packed)
        } else {
            Stream::create(dir, scope).map(Self::Flat)
        }
    }
    pub(crate) fn open(dir: &Path, scope: &Scope, head: Hash, packed: bool) -> Result<Self> {
        if packed {
            Packed::open(dir, scope, head).map(Self::Packed)
        } else {
            Stream::open(dir, scope, head).map(Self::Flat)
        }
    }
    pub(crate) fn observe_head(dir: &Path, scope: &Scope, packed: bool) -> Result<Hash> {
        if packed {
            Packed::<Record>::observe_head(dir, scope)
        } else {
            Stream::<Record>::observe_head(dir, scope)
        }
    }
    pub(crate) fn storage_head(&self) -> Hash {
        match self {
            Self::Flat(s) => s.storage_head(),
            Self::Packed(s) => s.storage_head(),
        }
    }
    pub(crate) fn record_count(&self) -> u64 {
        match self {
            Self::Flat(s) => s.record_count(),
            Self::Packed(s) => s.record_count(),
        }
    }
    pub(crate) fn layout_format(&self) -> &'static str {
        match self {
            Self::Flat(_) => FORMAT,
            Self::Packed(_) => PACKED_FORMAT,
        }
    }
    pub(crate) fn require_scope(&self, scope: &Scope) -> Result<()> {
        match self {
            Self::Flat(s) => s.require_scope(scope),
            Self::Packed(s) => s.require_scope(scope),
        }
    }
    pub(crate) fn require_unchanged(&self, head: Hash) -> Result<()> {
        match self {
            Self::Flat(s) => s.require_unchanged(head),
            Self::Packed(s) => s.require_unchanged(head),
        }
    }
    pub(crate) fn retained_usage_candidate(&self) -> Result<(usize, u64)> {
        match self {
            Self::Flat(s) => s.retained_usage_candidate(),
            Self::Packed(s) => s.retained_usage_candidate(),
        }
    }
    pub(crate) fn visit(
        &self,
        head: Hash,
        consumer: impl FnMut(&Record) -> Result<()>,
    ) -> Result<u64> {
        match self {
            Self::Flat(s) => s.visit(head, consumer),
            Self::Packed(s) => s.visit(head, consumer),
        }
    }
    pub(crate) fn records(
        &self,
        head: Hash,
    ) -> Result<Box<dyn Iterator<Item = Result<Record>> + '_>> {
        match self {
            Self::Flat(s) => Ok(Box::new(s.records(head)?)),
            Self::Packed(s) => Ok(Box::new(s.records(head)?)),
        }
    }
    pub(crate) fn append_accounted(
        &mut self,
        records: &[Record],
        head: Hash,
        files: usize,
        bytes: u64,
    ) -> Result<Hash> {
        match self {
            Self::Flat(s) => s.append_accounted(records, head, files, bytes),
            Self::Packed(s) => s.append_accounted(records, head, files, bytes),
        }
    }
    #[cfg(test)]
    pub(crate) fn append(&mut self, records: &[Record], head: Hash) -> Result<Hash> {
        self.append_accounted(records, head, 0, 0)
    }
    #[cfg(test)]
    pub(crate) fn interrupt_at(&mut self, boundary: u8) {
        match self {
            Self::Flat(s) => s.interrupt_at(boundary),
            Self::Packed(s) => s.interrupt_at(boundary),
        }
    }
}
impl body_witness::History for EventStream {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        self.require_scope(scope)
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        self.visit(self.storage_head(), consumer)
    }
}
