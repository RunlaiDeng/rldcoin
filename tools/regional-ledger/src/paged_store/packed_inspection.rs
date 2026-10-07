//! Read-only complete packed Native execution. No Store, signer or value adoption.
use super::*;
use crate::retained_pages::packed::archive::PackedArchiveCandidate;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PackedNativeBoundaryCandidate {
    pub currency: Hash,
    pub region: Hash,
    pub height: u64,
    pub finalized: Option<Hash>,
    pub epoch: Hash,
    pub ledger_root: Hash,
    pub record_count: u64,
}
pub(super) struct PackedHistory<'a> {
    pub(super) archive: &'a PackedArchiveCandidate<Record>,
    pub(super) scope: Scope,
    pub(super) current_head: Hash,
}
impl body_witness::History for PackedHistory<'_> {
    fn require_scope(&self, scope: &Scope) -> Result<()> {
        require(*scope == self.scope, "packed consumer scope differs")?;
        self.archive.require_scope(scope)
    }
    fn visit(&self, consumer: &mut dyn FnMut(&Record) -> Result<()>) -> Result<u64> {
        self.archive.visit(self.current_head, consumer)
    }
}
/// Both the storage head and ending Native boundary must come from the caller's
/// independent current anchors, never from the supplied archive or its sender.
/// The complete bootstrap verifies against the caller's currency/authority pins.
/// Result describes executed state only; it is not a Store or signer initializer.
pub fn inspect_packed_native_candidate(
    dir: &Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency_pin: Hash,
    storage_head: Hash,
    independently_latest: &PackedNativeBoundaryCandidate,
) -> Result<PackedNativeBoundaryCandidate> {
    require(
        independently_latest.currency == currency_pin,
        "packed Native current currency differs",
    )?;
    let header = Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: independently_latest.region,
    };
    let mut replay = Replay::new(&header, authority, currency_pin)?;
    let scope = header.scope(&replay.trust)?;
    let archive = PackedArchiveCandidate::<Record>::open(dir, &scope, storage_head)?;
    let source = PackedHistory {
        archive: &archive,
        scope,
        current_head: storage_head,
    };
    let count = archive.visit(storage_head, |record| {
        // Incident IDs alone cannot replace the Store's complete externally
        // retained incident proofs/guard. This inspection has no such store.
        if let Record::Incidents(ids) = record {
            require(
                ids.is_empty(),
                "packed inspection needs separate incident proof store",
            )?;
        }
        replay.apply_retained(record, &source)
    })?;
    let boundary = PackedNativeBoundaryCandidate {
        currency: replay.trust.currency()?,
        region: replay.chain.region,
        height: replay.chain.height(),
        finalized: replay.chain.finalized,
        epoch: replay.chain.epoch,
        ledger_root: replay.chain.ledger.root()?,
        record_count: count,
    };
    require(
        boundary == *independently_latest,
        "complete packed Native state differs from independent latest boundary",
    )?;
    Ok(boundary)
}
