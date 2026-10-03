use anyhow::{bail, Context};
use rld_core::{
    m0_candidate_replay::{
        transcript::{
            ReplayFrame, MAX_REPLAY_FRAME_BYTES, MAX_REPLAY_TRANSCRIPT_BYTES,
            MAX_REPLAY_TRANSCRIPT_RECORDS,
        },
        M0CandidateReplay,
    },
    AdmissionHash32,
};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
};

pub struct HistoryQueries<'a> {
    pub required_admission_entries: &'a [String],
    pub observe_admission_at_record: Option<usize>,
    pub require_observed_inclusion: bool,
    pub inspect_upgrade_intent: Option<&'a Path>,
    pub inspect_upgrade_schedule: Option<&'a Path>,
}

pub fn verify(
    manifest: &Path,
    pin: &str,
    history: &Path,
    expected_height: u128,
    expected_root: &str,
    queries: HistoryQueries<'_>,
) -> anyhow::Result<()> {
    let required_admission_entries = queries.required_admission_entries;
    if queries
        .observe_admission_at_record
        .is_some_and(|n| n == 0 || n > MAX_REPLAY_TRANSCRIPT_RECORDS)
        || (queries.require_observed_inclusion && queries.observe_admission_at_record.is_none())
    {
        bail!("observation requires a record between 1 and the local transcript record limit");
    }
    if required_admission_entries.len() > 64 {
        bail!("at most 64 required Admission entries are allowed");
    }
    let mut required = std::collections::BTreeSet::new();
    for value in required_admission_entries {
        let id = AdmissionHash32::from_hex(value).map_err(anyhow::Error::msg)?;
        if id.is_zero() || !required.insert(id) {
            bail!("required Admission entry IDs must be nonzero and unique");
        }
    }
    AdmissionHash32::from_hex(pin).map_err(anyhow::Error::msg)?;
    AdmissionHash32::from_hex(expected_root).map_err(anyhow::Error::msg)?;
    let mut bytes = Vec::new();
    File::open(manifest)?.take(65_537).read_to_end(&mut bytes)?;
    let mut verifier =
        M0CandidateReplay::from_pinned_genesis(&bytes, pin).map_err(anyhow::Error::msg)?;
    let file = File::open(history).context("cannot open candidate history")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_REPLAY_TRANSCRIPT_BYTES {
        bail!("candidate history must be a regular file within the 128 MiB local limit");
    }
    let mut reader = BufReader::new(file);
    let mut count = 0usize;
    let mut total = 0u64;
    let mut observation = None;
    loop {
        let mut line = Vec::new();
        (&mut reader)
            .take(MAX_REPLAY_FRAME_BYTES as u64 + 2)
            .read_until(b'\n', &mut line)?;
        if line.is_empty() {
            break;
        }
        count += 1;
        total = total
            .checked_add(line.len() as u64)
            .context("transcript byte count overflow")?;
        if count > MAX_REPLAY_TRANSCRIPT_RECORDS || total > MAX_REPLAY_TRANSCRIPT_BYTES {
            bail!("candidate history exceeds its local record or byte limit");
        }
        if line.pop() != Some(b'\n') {
            bail!("candidate history has a torn or oversized frame at record {count}");
        }
        ReplayFrame::decode_line(&line)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("candidate history decode failed at record {count}"))?
            .replay(&mut verifier)
            .map_err(anyhow::Error::msg)
            .with_context(|| {
                format!("candidate history semantic replay failed at record {count}")
            })?;
        if queries.observe_admission_at_record == Some(count) {
            observation = Some(verifier.observe_admission().map_err(anyhow::Error::msg)?);
        }
    }
    let ledger = verifier.ledger();
    let root = ledger.state_root()?;
    if u128::from(ledger.height) != expected_height || root != expected_root {
        bail!("candidate history does not reach the independently expected final height/root");
    }
    let reconciliation = if queries.observe_admission_at_record.is_some() {
        let observation = observation
            .as_ref()
            .context("observation record is absent from this history")?;
        let reconciliation = verifier
            .reconcile_admission_observation(observation)
            .map_err(anyhow::Error::msg)?;
        if queries.require_observed_inclusion && !reconciliation.all_observed_entries_included() {
            bail!("observed Admission entries remain unresolved; no complete finalized inclusion");
        }
        Some(reconciliation.report())
    } else {
        None
    };
    let mut inclusions = Vec::new();
    for id in required {
        let included = verifier
            .verified_admission_inclusion(id)
            .map_err(anyhow::Error::msg)?
            .with_context(|| {
                format!(
                    "required Admission entry {} is not finalized in any checkpoint",
                    id.to_hex()
                )
            })?;
        inclusions.push(included.report());
    }
    let mut report = serde_json::json!({
        "result": "PASS", "scope": "PINNED_GENESIS_CANDIDATE_SEMANTIC_REPLAY",
        "manifest_sha256": verifier.manifest_sha256(), "records": count,
        "final_height": ledger.height.to_string(), "final_state_root": root,
        "retained_sidecar_bytes": verifier.retained_sidecar_bytes(),
        "value_cap": "VALUE_CAP_0", "live_authorization": false,
        "independent_full_client": false, "durable_role_state_verified": false,
    });
    if !required_admission_entries.is_empty() {
        report["verified_admission_inclusions"] = serde_json::to_value(inclusions)?;
    }
    if let Some(reconciliation) = reconciliation {
        report["admission_observation_reconciliation"] = serde_json::to_value(reconciliation)?;
    }
    if let Some(path) = queries.inspect_upgrade_intent {
        let file = File::open(path).context("cannot open draft upgrade intent")?;
        if !file.metadata()?.is_file() {
            bail!("draft upgrade intent must be a regular file");
        }
        let mut bytes = Vec::new();
        file.take(16_385).read_to_end(&mut bytes)?;
        if bytes.len() > 16_384 {
            bail!("draft upgrade intent exceeds 16 KiB");
        }
        let intent = serde_json::from_slice(&bytes).context("invalid draft upgrade intent")?;
        report["upgrade_intent_inspection"] = serde_json::to_value(
            verifier
                .inspect_upgrade_intent(&intent)
                .map_err(anyhow::Error::msg)?,
        )?;
    }
    if let Some(path) = queries.inspect_upgrade_schedule {
        let file = File::open(path).context("cannot open upgrade schedule")?;
        if !file.metadata()?.is_file() {
            bail!("upgrade schedule must be a regular file");
        }
        let mut bytes = Vec::new();
        file.take(16_385).read_to_end(&mut bytes)?;
        if bytes.len() > 16_384 {
            bail!("upgrade schedule exceeds 16 KiB");
        }
        let schedule = serde_json::from_slice(&bytes).context("invalid upgrade schedule")?;
        report["upgrade_schedule_inspection"] = serde_json::to_value(
            verifier
                .inspect_upgrade_schedule(&schedule)
                .map_err(anyhow::Error::msg)?,
        )?;
    }
    println!("{report}");
    Ok(())
}
