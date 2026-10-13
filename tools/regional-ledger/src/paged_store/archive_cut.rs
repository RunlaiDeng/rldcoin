//! One exact historical state from complete Native replay; no live-state authority.
use super::{packed_inspection::PackedHistory, *};
use crate::retained_pages::packed::archive::PackedArchiveCandidate;

pub const HISTORICAL_ARCHIVE_QUERY_FORMAT: &str = "RLD-HISTORICAL-ARCHIVE-QUERY-CANDIDATE-V1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalArchiveQueryCandidate {
    pub format: String,
    pub region: Hash,
    pub checkpoint: Hash,
}

/// Scalar historical observation only. No deserializer or initializer consumes it.
#[derive(Debug, Serialize)]
pub struct HistoricalArchiveObservationCandidate {
    pub format: &'static str,
    pub currency: Hash,
    pub trust_binding: Hash,
    pub request_commitment: Hash,
    pub selected: Statement,
    pub selected_ledger_root: Hash,
    pub issued: Amount,
    pub liquid: Amount,
    pub escrow: Amount,
    pub pending_transfer: Amount,
    pub archive_record_count: u64,
    pub archive_final_checkpoint: Hash,
    pub archive_final_height: u64,
    pub complete_genesis_replay: bool,
    pub local_history_only: bool,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub current_spendability_authority: bool,
    pub independent_freshness_verified: bool,
    pub incident_safety_verified: bool,
    pub import_authority: bool,
    pub recovery_authority: bool,
}

/// Authority and currency pins are independently supplied. The carried head binds
/// the entire archive's bytes; a sender may supply an older valid archive. This
/// entry does not weaken the separately pinned latest-state recovery inspector.
/// Only local certificates under the original paged BFT admission are supported.
/// Unknown foreign closure refuses, including anywhere after the selected point.
pub fn inspect_historical_archive_candidate(
    dir: &Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency_pin: Hash,
    carried_head: Hash,
    query: &HistoricalArchiveQueryCandidate,
) -> Result<HistoricalArchiveObservationCandidate> {
    ensure_not_restoring(dir)?;
    require(
        query.format == HISTORICAL_ARCHIVE_QUERY_FORMAT
            && !query.checkpoint.is_zero()
            && !currency_pin.is_zero(),
        "historical archive exact query format/checkpoint/currency required",
    )?;
    let header = Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: query.region,
    };
    let mut replay = Replay::new(&header, authority, currency_pin)?;
    require(
        replay.trust.region(query.region)?.rules == crate::paged_bft::RULES,
        "historical archive requires original paged BFT admission",
    )?;
    let scope = header.scope(&replay.trust)?;
    let request_commitment = id(
        "historical-native-archive-request-v1",
        &(replay.trust.binding, carried_head, query),
    )?;
    // This exact raw format never learns a lossless manifest or adopts a newer
    // consensus profile from archive metadata.
    let archive = PackedArchiveCandidate::<Record>::open(dir, &scope, carried_head)?;
    let history = PackedHistory {
        archive: &archive,
        scope,
        current_head: carried_head,
    };
    let mut selected = None;
    let count = archive.visit(carried_head, |record| {
        let Record::Certified(snapshot) = record else {
            return Err("historical archive requires complete local certificates only".into());
        };
        require(
            snapshot.epochs.is_empty()
                && snapshot.statement.epoch
                    == epoch::Registry::initial(&replay.trust, query.region)?,
            "historical archive initial epoch required",
        )?;
        replay.apply_retained(record, &history)?;
        require(
            replay.chain.ledger.imports.is_empty(),
            "historical archive foreign import closure unsupported",
        )?;
        let checkpoint = snapshot.statement.id()?;
        if selected.is_none() && checkpoint == query.checkpoint {
            require(
                replay.chain.finalized == Some(checkpoint)
                    && replay.chain.height() == snapshot.statement.height,
                "historical archive selection was not the executed current certificate",
            )?;
            // Do not retain another Ledger, or derive one from a page/hash. Only
            // this invocation's complete native execution supplies these values.
            let totals = conservation_with_escrow(std::slice::from_ref(&replay.chain))?;
            selected = Some((
                snapshot.statement.clone(),
                replay.chain.ledger.root()?,
                totals,
            ));
        }
        // A later duplicate still fully authenticates above, but cannot recapture
        // the ending ledger under this historical checkpoint's identity.
        Ok(())
    })?;
    // The complete traversal has now checked every record and the final count/head.
    let (selected, selected_ledger_root, (issued, liquid, escrow, pending_transfer)) =
        selected.ok_or("historical archive selected checkpoint absent")?;
    let archive_final_checkpoint = replay
        .chain
        .finalized
        .ok_or("historical archive has no final certificate")?;
    let ending = replay.evidence.snapshot(archive_final_checkpoint)?;
    require(
        ending.statement.height == replay.chain.height(),
        "historical archive ending state is not finalized",
    )?;
    let result = HistoricalArchiveObservationCandidate {
        format: "RLD-HISTORICAL-ARCHIVE-OBSERVATION-CANDIDATE-V1",
        currency: currency_pin,
        trust_binding: replay.trust.binding,
        request_commitment,
        selected,
        selected_ledger_root,
        issued,
        liquid,
        escrow,
        pending_transfer,
        archive_record_count: count,
        archive_final_checkpoint,
        archive_final_height: replay.chain.height(),
        complete_genesis_replay: true,
        local_history_only: true,
        ledger_changed: false,
        signing_authority: false,
        current_spendability_authority: false,
        independent_freshness_verified: false,
        incident_safety_verified: false,
        import_authority: false,
        recovery_authority: false,
    };
    encode("historical-native-archive-observation-v1", &result)?;
    Ok(result)
}
