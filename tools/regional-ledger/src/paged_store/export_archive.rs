//! Complete signed source-history inspection beyond one contact envelope.
//! Verification-only candidate; ordinary contact/import rules remain unchanged.
use super::{packed_inspection::PackedHistory, *};
use crate::retained_pages::packed::archive::PackedArchiveCandidate;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportArchiveQueryCandidate {
    pub source: Hash,
    pub destination: Hash,
    pub export: Hash,
}

/// An executed historical source observation, never an import or freshness token.
/// No Deserialize implementation or Store/signer initializer consumes this result.
#[derive(Debug, Serialize)]
pub struct ExportArchiveObservationCandidate {
    pub format: &'static str,
    pub currency: Hash,
    pub source_checkpoint: Hash,
    pub source_height: u64,
    pub record_count: u64,
    pub export: Export,
    pub complete_genesis_replay: bool,
    pub remote_current_state_known: bool,
    pub incident_safety_qualified: bool,
    pub import_authority: bool,
    pub recipient_maturity_qualified: bool,
    pub owner_signing_authority: bool,
}

/// Currency and authority pins come from the receiver's adopted trust, independently
/// of the supplied history. `carried_head` binds bytes only: the sender may choose
/// an older valid history. Every complete certificate, owner command and Native
/// transition must execute from signed genesis before returning any observation.
/// This narrow candidate accepts local certificates only. It cannot conceal a
/// missing foreign proof/receipt/incident by treating its identifier as authority.
/// Existing per-record, page, active64 and aggregate archive bounds all apply.
pub fn inspect_export_archive_candidate(
    dir: &Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency_pin: Hash,
    carried_head: Hash,
    query: &ExportArchiveQueryCandidate,
) -> Result<ExportArchiveObservationCandidate> {
    let header = Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: query.source,
    };
    let mut replay = Replay::new(&header, authority, currency_pin)?;
    replay.trust.region(query.destination)?;
    require(
        query.source != query.destination,
        "export archive route is local",
    )?;
    let scope = header.scope(&replay.trust)?;
    let archive = PackedArchiveCandidate::<Record>::open(dir, &scope, carried_head)?;
    let history = PackedHistory {
        archive: &archive,
        scope,
        current_head: carried_head,
    };
    let count = archive.visit(carried_head, |record| {
        require(
            matches!(record, Record::Certified(_)),
            "export archive candidate requires complete local certificates only",
        )?;
        replay.apply_retained(record, &history)
    })?;
    let finalized = replay
        .chain
        .finalized
        .ok_or("export archive has no source finality")?;
    let snapshot = replay.evidence.snapshot(finalized)?;
    require(
        snapshot.statement.height == replay.chain.height(),
        "export archive source tail is not finalized",
    )?;
    let export = replay
        .chain
        .ledger
        .exports
        .get(&query.export)
        .ok_or("export absent from fully executed source archive")?
        .clone();
    require(
        export.id == query.export
            && export.source == query.source
            && export.destination == query.destination
            && export.height <= snapshot.statement.height,
        "export archive differs from exact expected route",
    )?;
    replay.chain.ledger.audit()?;
    Ok(ExportArchiveObservationCandidate {
        format: "RLD-CERTIFIED-EXPORT-ARCHIVE-OBSERVATION-CANDIDATE-V1",
        currency: replay.trust.currency()?,
        source_checkpoint: finalized,
        source_height: replay.chain.height(),
        record_count: count,
        export,
        complete_genesis_replay: true,
        remote_current_state_known: false,
        incident_safety_qualified: false,
        import_authority: false,
        recipient_maturity_qualified: false,
        owner_signing_authority: false,
    })
}
