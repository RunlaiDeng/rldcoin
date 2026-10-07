//! Bounded public append archive codec and independently selected caller inputs.
use crate::{read_owned_public_candidate as read, trusted_policy_observation_candidate};
use rld_core::{
    hybrid_authorization::{HybridObservationCandidateV1, HybridPolicyTrustV1, HybridPurposeV1},
    hybrid_permanent_import_archive::{
        verify_hybrid_permanent_import_archive_candidate,
        PermanentImportArchiveAnchorCandidateV1 as Anchor,
        PermanentImportArchiveEntryCandidateV1 as Entry, MAX_APPEND_ARCHIVE_BYTES_CANDIDATE,
        MAX_APPEND_ARCHIVE_ENTRIES_CANDIDATE,
    },
};
use serde::Deserialize;

pub const DOMAIN: &[u8] = b"RLD-PERMANENT-IMPORT-APPEND-ARCHIVE-CANDIDATE-V1\0";
pub const MAX_WIRE: usize = MAX_APPEND_ARCHIVE_BYTES_CANDIDATE + DOMAIN.len() + 2 + 64 * 8;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicAnchor {
    current_root: String,
    key_count: u32,
    next_nonce: u64,
    archive_head: String,
    caller_locks_root: String,
}
impl PublicAnchor {
    fn decode(self) -> Result<Anchor, String> {
        Ok(Anchor {
            current_root: crate::fixed(&self.current_root)?,
            key_count: self.key_count,
            next_nonce: self.next_nonce,
            archive_head: crate::fixed(&self.archive_head)?,
            caller_locks_root: crate::fixed(&self.caller_locks_root)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    current_epoch: u64,
    next_nonce: u64,
    policy_trust: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Caller {
    initial: PublicAnchor,
    latest: PublicAnchor,
    observations: Vec<Observation>,
}
fn take<'a>(raw: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = offset.checked_add(n).ok_or("archive length overflow")?;
    let value = raw.get(*offset..end).ok_or("archive truncated")?;
    *offset = end;
    Ok(value)
}
pub fn decode(raw: &[u8]) -> Result<Vec<Entry<'_>>, String> {
    if raw.len() > MAX_WIRE || !raw.starts_with(DOMAIN) {
        return Err("archive domain/byte bound differs".into());
    }
    let mut offset = DOMAIN.len();
    let count = u16::from_be_bytes(take(raw, &mut offset, 2)?.try_into().unwrap()) as usize;
    if count == 0 || count > MAX_APPEND_ARCHIVE_ENTRIES_CANDIDATE {
        return Err("archive entry count differs".into());
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let query = take(raw, &mut offset, 32)?.try_into().unwrap();
        let pn = u32::from_be_bytes(take(raw, &mut offset, 4)?.try_into().unwrap()) as usize;
        if pn > 32768 {
            return Err("proof exceeds bound".into());
        }
        let proof = take(raw, &mut offset, pn)?;
        let en = u32::from_be_bytes(take(raw, &mut offset, 4)?.try_into().unwrap()) as usize;
        if en > 12288 {
            return Err("envelope exceeds bound".into());
        }
        let envelope = take(raw, &mut offset, en)?;
        entries.push(Entry {
            query,
            complete_proof: proof,
            detached_envelope: envelope,
        });
    }
    if offset != raw.len() {
        return Err("archive trailing bytes".into());
    }
    Ok(entries)
}
pub fn verify_files(
    policy_path: &str,
    caller_path: &str,
    archive_path: &str,
) -> Result<Result<Anchor, String>, String> {
    let (policy, current) = trusted_policy_observation_candidate(policy_path)?;
    if policy.purpose != HybridPurposeV1::PermanentImportAppend
        || current.policy_trust != HybridPolicyTrustV1::CurrentAndTrusted
        || current.current_epoch < policy.valid_from_epoch
        || current.current_epoch > policy.valid_until_epoch
    {
        return Ok(Err(
            "current independently trusted policy unavailable/expired".into(),
        ));
    }
    let caller: Caller = serde_json::from_slice(&read(caller_path, 16384)?)
        .map_err(|_| "caller malformed/unknown/duplicate field")?;
    let initial = caller.initial.decode()?;
    let latest = caller.latest.decode()?;
    if current.next_nonce != initial.next_nonce || caller.observations.len() > 64 {
        return Ok(Err("caller initial nonce/observations differ".into()));
    }
    if caller
        .observations
        .iter()
        .any(|x| x.current_epoch > current.current_epoch)
    {
        return Ok(Err("observation after current caller position".into()));
    }
    let observations = caller
        .observations
        .into_iter()
        .map(|x| {
            if x.current_epoch > current.current_epoch {
                return Err("observation after current caller position".into());
            }
            let policy_trust = match x.policy_trust.as_str() {
                "CURRENT_AND_TRUSTED" => HybridPolicyTrustV1::CurrentAndTrusted,
                "UNAVAILABLE" => HybridPolicyTrustV1::Unavailable,
                "REVOKED" => HybridPolicyTrustV1::Revoked,
                "BROKEN" => HybridPolicyTrustV1::Broken,
                _ => return Err("unknown observation trust".into()),
            };
            Ok(HybridObservationCandidateV1 {
                current_epoch: x.current_epoch,
                next_nonce: x.next_nonce,
                policy_trust,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let raw = read(archive_path, MAX_WIRE)?;
    let entries = match decode(&raw) {
        Ok(v) => v,
        Err(e) => return Ok(Err(e)),
    };
    Ok(verify_hybrid_permanent_import_archive_candidate(
        &policy,
        &initial,
        &entries,
        &observations,
        &latest,
    )
    .map_err(|e| e.to_string()))
}
