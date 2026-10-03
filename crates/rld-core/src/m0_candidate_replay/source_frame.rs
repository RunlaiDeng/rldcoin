//! Local raw-sidecar transport for role-local semantic replay. This does not
//! allocate a consensus tag or authorize an Admission checkpoint.
use super::{bounded_json_size, transcript::ReplayAdmissionSource};
use crate::{
    AdmissionLedgerAnchorV1, AdmissionSidecarSubmissionV1, AdmissionVerifiedHeaderSubmissionV1,
    BaselineAccessWorkV1, PermissionlessAdmissionEntryV1, PermissionlessAdmissionHeaderV1,
    MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES, MAX_ADMISSION_ENTRIES_PER_HEADER,
    MAX_ADMISSION_SIDECAR_BYTES,
};
use serde::{Deserialize, Serialize};

pub const SOURCE_FRAME_MAGIC: &[u8; 8] = b"M0ASRC01";
pub const SOURCE_FRAME_VERSION: &str = "RLD-M0-ADMISSION-SOURCE-V1";
pub const SOURCE_MANIFEST_MAX_BYTES: usize = 2 * 1024 * 1024;
pub const SOURCE_FRAME_MAX_BYTES: usize = 12
    + SOURCE_MANIFEST_MAX_BYTES
    + MAX_ADMISSION_ENTRIES_PER_HEADER * 8
    + MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES as usize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: String,
    entries: Vec<PermissionlessAdmissionEntryV1>,
    access_work: BaselineAccessWorkV1,
    header: PermissionlessAdmissionHeaderV1,
    ledger_anchor: AdmissionLedgerAnchorV1,
}

pub fn encode_source_frame(
    source: &AdmissionVerifiedHeaderSubmissionV1,
) -> Result<Vec<u8>, String> {
    if source.entries.len() > MAX_ADMISSION_ENTRIES_PER_HEADER {
        return Err("Admission source has too many entries".into());
    }
    let mut entries = source.entries.iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|s| s.entry.entry_id());
    let mut previous = None;
    let mut total = 0usize;
    for item in &entries {
        let id = item.entry.entry_id();
        if previous == Some(id)
            || item.payload.len() as u64 != item.entry.declared_bytes
            || item.entry.declared_bytes > MAX_ADMISSION_SIDECAR_BYTES
        {
            return Err(
                "Admission source repeats an entry or changes its bounded sidecar length".into(),
            );
        }
        previous = Some(id);
        total = total
            .checked_add(item.payload.len())
            .filter(|n| *n <= MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES as usize)
            .ok_or("Admission source sidecars exceed 64 MiB")?;
    }
    let manifest = Manifest {
        format_version: SOURCE_FRAME_VERSION.into(),
        entries: entries.iter().map(|s| s.entry.clone()).collect(),
        access_work: source.access_work.clone(),
        header: source.header.clone(),
        ledger_anchor: source.ledger_anchor.clone(),
    };
    bounded_json_size(&manifest, SOURCE_MANIFEST_MAX_BYTES)?;
    let json = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + json.len() + entries.len() * 8 + total);
    out.extend_from_slice(SOURCE_FRAME_MAGIC);
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(&json);
    for s in entries {
        out.extend_from_slice(&s.entry.declared_bytes.to_be_bytes());
        out.extend_from_slice(&s.payload);
    }
    Ok(out)
}

pub fn decode_source_frame(bytes: &[u8]) -> Result<AdmissionVerifiedHeaderSubmissionV1, String> {
    if bytes.len() < 12 || bytes.len() > SOURCE_FRAME_MAX_BYTES || &bytes[..8] != SOURCE_FRAME_MAGIC
    {
        return Err("invalid or oversized M0 Admission source frame".into());
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if length == 0 || length > SOURCE_MANIFEST_MAX_BYTES || length > bytes.len() - 12 {
        return Err("M0 Admission source manifest is missing, truncated or oversized".into());
    }
    let raw = &bytes[12..12 + length];
    let manifest: Manifest = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
    if manifest.format_version != SOURCE_FRAME_VERSION
        || manifest.entries.len() > MAX_ADMISSION_ENTRIES_PER_HEADER
        || serde_json::to_vec(&manifest).map_err(|e| e.to_string())? != raw
    {
        return Err("M0 Admission source manifest is not exact canonical typed JSON".into());
    }
    let mut entries = Vec::with_capacity(manifest.entries.len());
    let mut cursor = 12 + length;
    let mut total = 0usize;
    let mut previous = None;
    for entry in manifest.entries {
        let id = entry.entry_id();
        if previous.is_some_and(|p| p >= id) {
            return Err("M0 Admission source entries are not unique canonical order".into());
        }
        previous = Some(id);
        let raw_length = bytes
            .get(cursor..cursor + 8)
            .ok_or("missing M0 Admission sidecar length")?;
        let length = u64::from_be_bytes(raw_length.try_into().unwrap());
        if length != entry.declared_bytes || length > MAX_ADMISSION_SIDECAR_BYTES {
            return Err("M0 Admission sidecar length differs from its bounded signed entry".into());
        }
        let length = usize::try_from(length).map_err(|_| "M0 Admission sidecar length overflow")?;
        total = total
            .checked_add(length)
            .filter(|n| *n <= MAX_ADMISSION_CHECKPOINT_AVAILABILITY_BYTES as usize)
            .ok_or("M0 Admission sidecar aggregate exceeds 64 MiB")?;
        cursor += 8;
        let payload = bytes
            .get(cursor..cursor + length)
            .ok_or("truncated M0 Admission sidecar")?
            .to_vec();
        cursor += length;
        entries.push(AdmissionSidecarSubmissionV1 { entry, payload });
    }
    if cursor != bytes.len() {
        return Err("trailing M0 Admission source bytes".into());
    }
    Ok(AdmissionVerifiedHeaderSubmissionV1 {
        entries,
        access_work: manifest.access_work,
        header: manifest.header,
        ledger_anchor: manifest.ledger_anchor,
    })
}

impl ReplayAdmissionSource {
    pub fn into_submission(self) -> AdmissionVerifiedHeaderSubmissionV1 {
        AdmissionVerifiedHeaderSubmissionV1 {
            entries: self
                .entries
                .into_iter()
                .map(|s| AdmissionSidecarSubmissionV1 {
                    entry: s.entry,
                    payload: s.payload,
                })
                .collect(),
            access_work: self.access_work,
            header: self.header,
            ledger_anchor: self.ledger_anchor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m0_candidate_replay::transcript::{ReplayEvent, ReplayFrame};
    fn fixture() -> AdmissionVerifiedHeaderSubmissionV1 {
        let text = include_str!("../../../../vectors/m0-semantic-replay-v1/history.jsonl");
        text.lines()
            .find_map(
                |line| match ReplayFrame::decode_line(line.as_bytes()).unwrap().event {
                    ReplayEvent::AdmissionSource(s) => Some(s.into_submission()),
                    _ => None,
                },
            )
            .unwrap()
    }
    #[test]
    fn source_frame_preserves_raw_sidecars_and_refuses_ambiguous_frames() {
        let source = fixture();
        let bytes = encode_source_frame(&source).unwrap();
        let decoded = decode_source_frame(&bytes).unwrap();
        assert_eq!(decoded.header, source.header);
        assert_eq!(decoded.entries[0].payload, source.entries[0].payload);
        assert_eq!(encode_source_frame(&decoded).unwrap(), bytes);
        for n in [0, 7, 11, bytes.len() - 1] {
            assert!(decode_source_frame(&bytes[..n]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(decode_source_frame(&bad).is_err());
        let mut bad = bytes.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_source_frame(&bad).is_err());
        let n = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut bad = bytes.clone();
        bad[12 + n..20 + n].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode_source_frame(&bad).is_err());
        // Re-encoding rejects ignored inner fields as well as unknown top-level
        // fields. No Value intermediary truncates a U128 number.
        let mut extreme = fixture();
        extreme.entries[0].entry.expiry_height = u128::MAX;
        let roundtrip = decode_source_frame(&encode_source_frame(&extreme).unwrap()).unwrap();
        assert_eq!(roundtrip.entries[0].entry.expiry_height, u128::MAX);
        let raw = std::str::from_utf8(&bytes[12..12 + n]).unwrap();
        for raw in [
            format!(" {raw}"),
            raw.replacen("\"entries\":", "\"ignored\":true,\"entries\":", 1),
            raw.replacen(
                "\"format_version\":",
                "\"format_version\":\"duplicate\",\"format_version\":",
                1,
            ),
        ] {
            let mut changed = SOURCE_FRAME_MAGIC.to_vec();
            changed.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            changed.extend_from_slice(raw.as_bytes());
            changed.extend_from_slice(&bytes[12 + n..]);
            assert!(decode_source_frame(&changed).is_err());
        }
    }
    #[test]
    fn source_transport_keeps_eight_mib_sidecar_boundary_without_json_byte_arrays() {
        let mut source = fixture();
        source.entries[0].payload = vec![42; MAX_ADMISSION_SIDECAR_BYTES as usize];
        source.entries[0].entry.declared_bytes = MAX_ADMISSION_SIDECAR_BYTES;
        let bytes = encode_source_frame(&source).unwrap();
        assert!(bytes.len() < MAX_ADMISSION_SIDECAR_BYTES as usize + 16384);
        assert_eq!(
            decode_source_frame(&bytes).unwrap().entries[0].payload,
            source.entries[0].payload
        );
        source.entries[0].payload.push(0);
        source.entries[0].entry.declared_bytes += 1;
        assert!(encode_source_frame(&source).is_err());
        // This is codec boundary coverage only: replacing payload bytes does
        // not produce a valid signed entry or semantic authorization.
    }
}
