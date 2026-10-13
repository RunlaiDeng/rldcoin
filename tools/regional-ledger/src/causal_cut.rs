//! Authenticated historical accounting for bounded original full-prefix fixtures.
//!
//! The caller supplies the independently approved bootstrap, authority and
//! currency pin. Complete evidence, including later tails, follows Native
//! verification and its exact-duplicate reuse. No Store, incident archive,
//! current state, signing or freshness authority is inspected or created here.
//! This is not a global live balance oracle.
use super::*;

pub const FORMAT: &str = "RLD-HISTORICAL-CAUSAL-CUT-V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub region: Hash,
    pub checkpoint: Hash,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: String,
    pub currency: Hash,
    pub trust_binding: Hash,
    pub request_commitment: Hash,
    pub selected: Vec<Statement>,
    pub issued: Amount,
    pub liquid: Amount,
    pub escrow: Amount,
    pub pending_transfer: Amount,
    pub ledger_changed: bool,
    pub signing_authority: bool,
    pub current_spendability_authority: bool,
    pub independent_freshness_verified: bool,
    pub incident_safety_verified: bool,
}

fn covered(
    checkpoint: Hash,
    selected: &BTreeMap<Hash, Hash>,
    verified: &VerifiedEvidence,
) -> Result<()> {
    // Resolve both identities before ancestry: equality alone is not evidence.
    let dependency = verified.snapshot(checkpoint)?;
    let selected_id = selected
        .get(&dependency.statement.region)
        .ok_or("causal cut omits required source region")?;
    verified.snapshot(*selected_id)?;
    require(
        verified.descends_from(*selected_id, checkpoint)?,
        "selected history precedes required checkpoint",
    )
}

/// Authenticate complete evidence before releasing any selected-history totals.
/// Only homogeneous original full-prefix unanimous, original BFT or open-channel
/// BFT admissions are supported. Channel history is limited to Open and Reserve.
/// Newer profiles need their own complete dependency and incident integration; none
/// is coerced into these profiles. Input Chain/Ledger values are never authority.
pub fn inspect(
    bootstrap: &Bootstrap,
    authority: &str,
    currency_pin: Hash,
    evidence: &Evidence,
    selection: &[Selection],
) -> Result<Report> {
    require(!currency_pin.is_zero(), "causal cut requires currency pin")?;
    require(
        !selection.is_empty() && selection.len() <= 16,
        "causal cut selection bound",
    )?;
    require(
        !evidence.snapshots.is_empty() && evidence.snapshots.len() <= MAX_SNAPSHOTS,
        "causal cut evidence bound",
    )?;
    let request_commitment = id(
        "historical-causal-cut-request",
        &(
            FORMAT,
            bootstrap,
            authority,
            currency_pin,
            evidence,
            selection,
        ),
    )?;
    let trust = Trust::verify(bootstrap, authority, currency_pin)?;
    let unanimous = bootstrap.admissions.iter().all(|a| a.rules == DOMAIN);
    let original_bft = bootstrap.admissions.iter().all(|a| a.rules == bft::RULES);
    let open_channel_bft = bootstrap
        .admissions
        .iter()
        .all(|a| a.rules == channels::BFT_RULES);
    require(
        unanimous || original_bft || open_channel_bft,
        "causal cut supports only homogeneous original unanimous, original BFT or open-channel BFT admissions",
    )?;
    for snapshot in &evidence.snapshots {
        require(
            snapshot.base.is_none()
                && (snapshot.bft.is_some() == (original_bft || open_channel_bft))
                && snapshot.epochs.is_empty()
                && snapshot.statement.epoch
                    == epoch::Registry::initial(&trust, snapshot.statement.region)?
                && snapshot.blocks.len() <= MAX_BLOCKS
                && snapshot.blocks.iter().all(|block| {
                    block.commands.iter().all(|command| match command {
                        Command::Spend(_) | Command::Import { .. } => true,
                        Command::Channel(command) if open_channel_bft => matches!(
                            command.action.intent.action,
                            channels::Action::Open { .. } | channels::Action::Reserve { .. }
                        ),
                        _ => false,
                    })
                }),
            "causal cut unsupported history profile",
        )?;
    }
    // Do not deduplicate before authentication or stop at the selected prefix.
    let verified = VerifiedEvidence::verify(evidence, &trust)?;
    let mut selected = BTreeMap::new();
    let mut chains = Vec::new();
    let mut statements = Vec::new();
    for choice in selection {
        let snapshot = verified.snapshot(choice.checkpoint)?;
        require(
            snapshot.statement.region == choice.region && snapshot.statement.height > 0,
            "causal cut selected checkpoint identity",
        )?;
        require(
            selected.insert(choice.region, choice.checkpoint).is_none(),
            "causal cut duplicate selected region",
        )?;
        chains.push(verified.replay_extension(snapshot, &trust)?);
        statements.push(snapshot.statement.clone());
    }

    // Full prefixes include spent ancestors, not just surviving coin lineage.
    // Open/Reserve consume local replayed inputs and channel records; their
    // imported provenance remains in these prefixes and permanent import maps.
    // Extra valid later evidence is authenticated but does not advance this cut.
    let mut pending = selected.values().copied().collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    while let Some(checkpoint) = pending.pop_first() {
        if !visited.insert(checkpoint) {
            continue;
        }
        require(visited.len() <= MAX_SNAPSHOTS, "causal cut closure bound")?;
        covered(checkpoint, &selected, &verified)?;
        let snapshot = verified.snapshot(checkpoint)?;
        let mut dependencies = BTreeSet::new();
        dependencies.extend(snapshot.statement.previous);
        for block in &snapshot.blocks {
            dependencies.extend(block.header.anchor);
            for command in &block.commands {
                if let Command::Import { snapshot, .. } = command {
                    dependencies.insert(*snapshot);
                }
            }
        }
        for dependency in dependencies {
            covered(dependency, &selected, &verified)?;
            if !visited.contains(&dependency) {
                pending.insert(dependency);
            }
        }
        require(
            pending.len() <= MAX_SNAPSHOTS,
            "causal cut pending dependency bound",
        )?;
    }
    for chain in &chains {
        for (export_id, source_checkpoint) in &chain.ledger.imports {
            covered(*source_checkpoint, &selected, &verified)?;
            let source = verified.snapshot(*source_checkpoint)?;
            let export = verified.export(*source_checkpoint, *export_id)?;
            require(
                export.id == *export_id
                    && export.source == source.statement.region
                    && export.destination == chain.region
                    && export.source != chain.region
                    && export.height <= source.statement.height
                    && export == verified.export(selected[&export.source], *export_id)?,
                "causal cut imported export differs from selected source",
            )?;
        }
    }
    let (issued, liquid, escrow, pending_transfer) = conservation_with_escrow(&chains)?;
    let report = Report {
        format: FORMAT.into(),
        currency: currency_pin,
        trust_binding: trust.binding,
        request_commitment,
        selected: statements,
        issued,
        liquid,
        escrow,
        pending_transfer,
        ledger_changed: false,
        signing_authority: false,
        current_spendability_authority: false,
        independent_freshness_verified: false,
        incident_safety_verified: false,
    };
    encode("historical-causal-cut-report", &report)?;
    Ok(report)
}
