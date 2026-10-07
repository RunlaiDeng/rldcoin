//! Verification-only offline manifest adapter. Policy/observation are separate
//! independently authenticated caller inputs, never learned from arriving bytes.
use rld_core::{
    hybrid_archive::{
        verify_hybrid_archive_manifest_candidate, HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_WIRE_BYTES,
    },
    hybrid_authorization::{
        HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridPolicyTrustV1,
        HybridPurposeV1, HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
    },
};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedInput {
    profile: String,
    currency_root: String,
    region_root: String,
    purpose: HybridPurposeV1,
    valid_from_epoch: u64,
    valid_until_epoch: u64,
    ed_public_key: String,
    pq_public_key: String,
    current_epoch: u64,
    next_nonce: u64,
    policy_trust: String,
}
fn bounded(path: &str, max: usize) -> Result<Vec<u8>, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "public input unavailable")?;
    let m = f.metadata().map_err(|_| "public input stat unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
        || m.len() > max as u64
    {
        return Err("bounded owned private public input required".into());
    }
    let mut raw = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "public read unavailable")?;
    if raw.len() > max {
        return Err("public input grew beyond bound".into());
    }
    Ok(raw)
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("caller requires canonical hex".into());
    }
    hex::decode(s)
        .map_err(|_| "hex unavailable")?
        .try_into()
        .map_err(|_| "caller size differs".into())
}
pub fn verify_manifest_files(
    policy_path: &str,
    manifest_path: &str,
    envelope_path: &str,
) -> Result<
    Result<rld_core::hybrid_archive::HybridVerifiedArchiveManifestCandidateV1, String>,
    String,
> {
    let t: TrustedInput = serde_json::from_slice(&bounded(policy_path, 8192)?)
        .map_err(|_| "caller malformed/unknown/duplicate field")?;
    let obs = HybridObservationCandidateV1 {
        current_epoch: t.current_epoch,
        next_nonce: t.next_nonce,
        policy_trust: match t.policy_trust.as_str() {
            "CURRENT_AND_TRUSTED" => HybridPolicyTrustV1::CurrentAndTrusted,
            "UNAVAILABLE" => HybridPolicyTrustV1::Unavailable,
            "REVOKED" => HybridPolicyTrustV1::Revoked,
            "BROKEN" => HybridPolicyTrustV1::Broken,
            _ => return Err("unknown caller trust observation".into()),
        },
    };
    let policy = HybridPolicyCandidateV1 {
        profile: t.profile,
        currency_root: fixed(&t.currency_root)?,
        region_root: fixed(&t.region_root)?,
        purpose: t.purpose,
        valid_from_epoch: t.valid_from_epoch,
        valid_until_epoch: t.valid_until_epoch,
        ed_public_key: fixed(&t.ed_public_key)?,
        pq_public_key: Box::new(fixed(&t.pq_public_key)?),
    };
    let manifest = bounded(
        manifest_path,
        HYBRID_ARCHIVE_MANIFEST_CANDIDATE_MAX_WIRE_BYTES,
    )?;
    let envelope = bounded(envelope_path, HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES)?;
    Ok(
        verify_hybrid_archive_manifest_candidate(&policy, obs, &manifest, &envelope)
            .map_err(|e| e.to_string()),
    )
}
