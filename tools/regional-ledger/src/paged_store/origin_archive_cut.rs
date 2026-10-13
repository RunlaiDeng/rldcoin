//! Exact historical composition of two complete Native archives, without adoption.
use super::{packed_inspection::PackedHistory, *};
use crate::retained_pages::packed::archive::PackedArchiveCandidate;

pub const ORIGIN_ARCHIVE_CUT_FORMAT: &str = "RLD-ORIGIN-ARCHIVE-CUT-CANDIDATE-V1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginArchiveSelectionCandidate {
    pub region: Hash,
    pub checkpoint: Hash,
    pub carried_head: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginArchiveCutQueryCandidate {
    pub format: String,
    pub source: OriginArchiveSelectionCandidate,
    pub destination: OriginArchiveSelectionCandidate,
    pub export: Hash,
}

/// Scalars and certified statements only; no deserializer or state initializer.
#[derive(Debug, Serialize)]
pub struct OriginArchiveCutObservationCandidate {
    pub format: &'static str,
    pub currency: Hash,
    pub trust_binding: Hash,
    pub request_commitment: Hash,
    pub selected: [Statement; 2],
    pub issued: Amount,
    pub liquid: Amount,
    pub escrow: Amount,
    pub pending_transfer: Amount,
    pub source_record_count: u64,
    pub destination_record_count: u64,
    pub source_final_checkpoint: Hash,
    pub destination_final_checkpoint: Hash,
    pub source_final_height: u64,
    pub destination_final_height: u64,
    pub complete_genesis_replay: bool,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub current_spendability_authority: bool,
    pub independent_freshness_verified: bool,
    pub incident_safety_verified: bool,
    pub import_authority: bool,
    pub recovery_authority: bool,
}

fn selected_state(
    replay: &Replay,
    snapshot: &Snapshot,
    retained_bytes: usize,
) -> Result<(Statement, Chain, usize)> {
    require(
        replay.chain.finalized == Some(snapshot.statement.id()?)
            && replay.chain.height() == snapshot.statement.height,
        "origin archive cut selection is not the executed current certificate",
    )?;
    let bytes = crate::encoded_size::check(
        "origin-archive-selected-state-v1",
        &(&snapshot.statement, &replay.chain.ledger),
    )?;
    require(
        retained_bytes
            .checked_add(bytes)
            .is_some_and(|n| n <= MAX_BYTES),
        "origin archive cut aggregate selected state exceeds bound",
    )?;
    Ok((snapshot.statement.clone(), replay.chain.clone(), bytes))
}

fn finish(replay: &Replay, history: &PackedHistory<'_>, count: u64) -> Result<(Hash, u64)> {
    replay
        .executed
        .require_boundary(&history.scope, count, history.current_head)?;
    let checkpoint = replay
        .chain
        .finalized
        .ok_or("origin archive cut has no final certificate")?;
    require(
        replay.evidence.snapshot(checkpoint)?.statement.height == replay.chain.height(),
        "origin archive cut ending state is not finalized",
    )?;
    Ok((checkpoint, replay.chain.height()))
}

/// Independently pinned trust precedes both complete genesis replays. Archive
/// heads bind sender-selected bytes only. This narrow route admits one origin
/// export, one complete origin proof, and local spending at its destination.
/// It never opens a Store or changes ordinary import/recovery/consensus rules.
pub fn inspect_origin_archive_cut_candidate(
    source_dir: &Path,
    destination_dir: &Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency_pin: Hash,
    query: &OriginArchiveCutQueryCandidate,
) -> Result<OriginArchiveCutObservationCandidate> {
    ensure_not_restoring(source_dir)?;
    ensure_not_restoring(destination_dir)?;
    require(
        query.format == ORIGIN_ARCHIVE_CUT_FORMAT
            && !currency_pin.is_zero()
            && !query.export.is_zero()
            && !query.source.checkpoint.is_zero()
            && !query.destination.checkpoint.is_zero()
            && !query.source.carried_head.is_zero()
            && !query.destination.carried_head.is_zero()
            && query.source.region != query.destination.region
            && bootstrap.admissions.len() == 2,
        "origin archive cut requires exact format, two regions and nonzero pins",
    )?;
    let source_header = Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: query.source.region,
    };
    let mut source = Replay::new(&source_header, authority, currency_pin)?;
    require(
        source.trust.region(query.source.region)?.rules == crate::paged_bft::RULES
            && source.trust.region(query.source.region)?.region == source.trust.currency.origin
            && source.trust.region(query.destination.region)?.rules
                == crate::paged_bft::ORIGIN_HISTORY_RULES,
        "origin archive cut requires exact origin and complete-history admissions",
    )?;
    let trust_binding = source.trust.binding;
    let request_commitment = id(
        "origin-native-archive-cut-request-v1",
        &(trust_binding, currency_pin, query),
    )?;
    let scope = source_header.scope(&source.trust)?;
    let archive =
        PackedArchiveCandidate::<Record>::open(source_dir, &scope, query.source.carried_head)?;
    let history = PackedHistory {
        archive: &archive,
        scope,
        current_head: query.source.carried_head,
    };
    // Private comparison witnesses arise only AFTER complete native execution.
    // They never supply state, skip envelope authentication or survive this call.
    let mut source_bodies = BTreeMap::new();
    let mut source_selected = None;
    let source_record_count = archive.visit(history.current_head, |record| {
        let Record::Certified(snapshot) = record else {
            return Err("origin archive cut source requires local certificates only".into());
        };
        for command in snapshot.blocks.iter().flat_map(|b| &b.commands) {
            require(
                matches!(command, Command::Spend(_)),
                "origin archive cut source command unsupported",
            )?;
        }
        source.apply_retained(record, &history)?;
        require(
            source.chain.ledger.imports.is_empty()
                && source.chain.ledger.channel_state.is_none()
                && source.chain.ledger.exports.iter().all(|(key, export)| {
                    *key == query.export
                        && export.id == query.export
                        && export.source == query.source.region
                        && export.destination == query.destination.region
                }),
            "origin archive cut source contains another value route",
        )?;
        let checkpoint = snapshot.statement.id()?;
        let identity = (checkpoint, body(snapshot)?);
        if let Some(old) = source_bodies.get(&snapshot.statement.height) {
            require(*old == identity, "origin archive cut source branch differs")?;
        } else {
            require(
                source_bodies.len() < MAX_COINS,
                "origin archive cut source comparison bound",
            )?;
            source_bodies.insert(snapshot.statement.height, identity);
            crate::encoded_size::check("origin-archive-cut-body-witnesses-v1", &source_bodies)?;
        }
        if source_selected.is_none() && checkpoint == query.source.checkpoint {
            source_selected = Some(selected_state(&source, snapshot, 0)?);
        }
        Ok(())
    })?;
    let (source_final_checkpoint, source_final_height) =
        finish(&source, &history, source_record_count)?;
    let (source_statement, source_chain, source_bytes) =
        source_selected.ok_or("origin archive cut source selection absent")?;
    // No full ending source ledger/evidence is needed for historical composition.
    drop(source);

    let destination_header = Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: query.destination.region,
    };
    let mut destination = Replay::new(&destination_header, authority, currency_pin)?;
    require(
        destination.trust.binding == trust_binding,
        "origin archive cut trust differs",
    )?;
    let scope = destination_header.scope(&destination.trust)?;
    let archive = PackedArchiveCandidate::<Record>::open(
        destination_dir,
        &scope,
        query.destination.carried_head,
    )?;
    let history = PackedHistory {
        archive: &archive,
        scope,
        current_head: query.destination.carried_head,
    };
    let mut origin = None;
    let mut imported = BTreeMap::new();
    let mut destination_selected = None;
    let destination_record_count = archive.visit(history.current_head, |record| {
        match record {
            Record::OriginHistory(proof) => {
                require(
                    destination.executed.count() == 0
                        && origin.is_none()
                        && proof.source == query.source.region
                        && proof.destination == query.destination.region
                        && proof.export == query.export,
                    "origin archive cut requires one first exact origin proof",
                )?;
                destination.apply_retained(record, &history)?;
                // Both archives' complete certificates authenticate independently.
                // Equal Export amounts or matching proof tails alone do not prove
                // that their whole source histories describe the same branch.
                for snapshot in &proof.snapshots {
                    require(
                        source_bodies.get(&snapshot.statement.height)
                            == Some(&(snapshot.statement.id()?, body(snapshot)?)),
                        "origin archive cut embedded source branch differs",
                    )?;
                }
                let last = proof
                    .snapshots
                    .last()
                    .ok_or("origin archive cut empty proof")?;
                let checkpoint = last.statement.id()?;
                let export = destination
                    .evidence
                    .export(checkpoint, query.export)?
                    .clone();
                origin = Some((checkpoint, last.statement.height, export));
            }
            Record::Certified(snapshot) => {
                let (proof_checkpoint, _, _) = origin
                    .as_ref()
                    .ok_or("origin archive cut proof must precede local history")?;
                for command in snapshot.blocks.iter().flat_map(|b| &b.commands) {
                    let supported = match command {
                        Command::Spend(signed) => signed.intent.destination.is_none(),
                        Command::Import { snapshot, export } => {
                            snapshot == proof_checkpoint && *export == query.export
                        }
                        _ => false,
                    };
                    require(
                        supported,
                        "origin archive cut destination command unsupported",
                    )?;
                }
                let previous_height = destination.chain.height();
                destination.apply_retained(record, &history)?;
                if destination.chain.height() > previous_height {
                    // Carried preceding blocks and old duplicates are authenticated
                    // again above, but do not execute their Import a second time.
                    for command in &snapshot
                        .blocks
                        .last()
                        .ok_or("origin archive cut block missing")?
                        .commands
                    {
                        if let Command::Import { snapshot, export } = command {
                            require(
                                imported.insert(*export, *snapshot).is_none(),
                                "origin archive cut repeated executed import",
                            )?;
                        }
                    }
                }
                require(
                    destination.chain.ledger.exports.is_empty()
                        && destination.chain.ledger.channel_state.is_none()
                        && destination.chain.ledger.imports == imported,
                    "origin archive cut destination permanent closure differs",
                )?;
                if destination_selected.is_none()
                    && snapshot.statement.id()? == query.destination.checkpoint
                {
                    // This native state contains the exact permanent map at the
                    // selected point. Later imports authenticate without changing it.
                    destination_selected =
                        Some(selected_state(&destination, snapshot, source_bytes)?);
                }
            }
            _ => return Err("origin archive cut destination record unsupported".into()),
        }
        Ok(())
    })?;
    let (destination_final_checkpoint, destination_final_height) =
        finish(&destination, &history, destination_record_count)?;
    let (destination_statement, destination_chain, _) =
        destination_selected.ok_or("origin archive cut destination selection absent")?;
    let (proof_checkpoint, proof_height, export) =
        origin.ok_or("origin archive cut complete origin proof absent")?;
    if !destination_chain.ledger.imports.is_empty() {
        require(
            destination_chain.ledger.imports.len() == 1
                && destination_chain.ledger.imports.get(&query.export) == Some(&proof_checkpoint)
                && source_statement.height >= proof_height
                && source_chain.ledger.exports.get(&query.export) == Some(&export),
            "origin archive cut selected source does not cover complete imported dependency",
        )?;
    }
    let (issued, liquid, escrow, pending_transfer) =
        conservation_with_escrow(&[source_chain, destination_chain])?;
    let observation = OriginArchiveCutObservationCandidate {
        format: "RLD-ORIGIN-ARCHIVE-CUT-OBSERVATION-CANDIDATE-V1",
        currency: currency_pin,
        trust_binding,
        request_commitment,
        selected: [source_statement, destination_statement],
        issued,
        liquid,
        escrow,
        pending_transfer,
        source_record_count,
        destination_record_count,
        source_final_checkpoint,
        destination_final_checkpoint,
        source_final_height,
        destination_final_height,
        complete_genesis_replay: true,
        ledger_changed: false,
        signing_authority: false,
        current_spendability_authority: false,
        independent_freshness_verified: false,
        incident_safety_verified: false,
        import_authority: false,
        recovery_authority: false,
    };
    encode("origin-native-archive-cut-observation-v1", &observation)?;
    Ok(observation)
}
