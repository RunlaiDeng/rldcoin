//! Verification-only cold archive adapter: independent initial anchor and caller
//! latest head/observations are separate from complete public entry files.
//! Bounded leaf-name openat under a retained owned directory; no installation.
use rld_core::hybrid_authorization::{
    verify_hybrid_renewal_archive_candidate, HybridObservationCandidateV1, HybridPolicyCandidateV1,
    HybridPolicyTrustV1, HybridPurposeV1, HybridRenewalAnchorCandidateV1,
    HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES, HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES,
    HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
};
use serde::Deserialize;
use sha2::{Digest, Sha512};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};
const CALLER_PROFILE: &str = "RLDCOIN-HYBRID-RENEWAL-ARCHIVE-CALLER-CANDIDATE-V1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedAnchor {
    profile: String,
    currency_root: String,
    region_root: String,
    purpose: HybridPurposeV1,
    valid_from_epoch: u64,
    valid_until_epoch: u64,
    ed_public_key: String,
    pq_public_key: String,
    crypto_era: u64,
    key_epoch: u64,
    next_nonce: u64,
    last_transition: String,
    caller_locks_root: String,
    consumed_exports_root: String,
    current_epoch: u64,
    policy_trust: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryObservation {
    file: String,
    current_epoch: u64,
    next_nonce: u64,
    policy_trust: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedArchive {
    profile: String,
    expected_latest_transition: String,
    entries: Vec<EntryObservation>,
}
fn read_file(f: File, max: usize) -> Result<Vec<u8>, String> {
    let m = f.metadata().map_err(|_| "public input stat unavailable")?;
    if !m.is_file()
        || m.len() > max as u64
        || m.uid() != unsafe { libc::getuid() }
        || m.mode() & 0o077 != 0
    {
        return Err("input requires bounded owned private regular file".into());
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "public read failed")?;
    if b.len() > max {
        return Err("public input grew beyond bound".into());
    }
    Ok(b)
}
fn bounded(path: &str, max: usize) -> Result<Vec<u8>, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "bounded public input unavailable")?;
    read_file(f, max)
}
fn entry(dir: &File, name: &str) -> Result<Vec<u8>, String> {
    if name.is_empty()
        || name.len() > 96
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("entry needs a bounded ASCII leaf name".into());
    }
    let name = CString::new(name).map_err(|_| "entry name malformed")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("complete public entry unavailable".into());
    }
    // Ownership transfers exactly once; File closes the descriptor on all paths.
    read_file(
        unsafe { File::from_raw_fd(fd) },
        HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
    )
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("caller needs exact canonical hex".into());
    }
    hex::decode(s)
        .map_err(|_| "caller hex invalid")?
        .try_into()
        .map_err(|_| "caller size invalid".into())
}
fn trust(s: &str) -> Result<HybridPolicyTrustV1, String> {
    match s {
        "CURRENT_AND_TRUSTED" => Ok(HybridPolicyTrustV1::CurrentAndTrusted),
        "BROKEN" => Ok(HybridPolicyTrustV1::Broken),
        "REVOKED" => Ok(HybridPolicyTrustV1::Revoked),
        "UNAVAILABLE" => Ok(HybridPolicyTrustV1::Unavailable),
        _ => Err("unknown caller trust observation".into()),
    }
}
fn verify(args: &[String]) -> Result<Result<HybridRenewalAnchorCandidateV1, String>, String> {
    if args.len() != 4 && !(args.len() == 8 && args[4] == "--authorized-manifest") {
        return Err("expected trusted initial anchor, caller latest/observations, entry directory; optionally --authorized-manifest plus separate policy, manifest and envelope".into());
    }
    let t: TrustedAnchor = serde_json::from_slice(&bounded(&args[1], 8192)?)
        .map_err(|_| "anchor malformed/duplicate/unknown")?;
    let caller: TrustedArchive = serde_json::from_slice(&bounded(&args[2], 32768)?)
        .map_err(|_| "caller archive metadata malformed/duplicate/unknown")?;
    if caller.profile != CALLER_PROFILE
        || caller.entries.is_empty()
        || caller.entries.len() > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES
    {
        return Err("caller archive profile or entry count invalid".into());
    }
    let first = &caller.entries[0];
    if first.current_epoch != t.current_epoch
        || first.next_nonce != t.next_nonce
        || trust(&first.policy_trust)? != trust(&t.policy_trust)?
    {
        return Err("independent initial observation differs".into());
    }
    let expected = fixed(&caller.expected_latest_transition)?;
    let initial = HybridRenewalAnchorCandidateV1 {
        policy: HybridPolicyCandidateV1 {
            profile: t.profile,
            currency_root: fixed(&t.currency_root)?,
            region_root: fixed(&t.region_root)?,
            purpose: t.purpose,
            valid_from_epoch: t.valid_from_epoch,
            valid_until_epoch: t.valid_until_epoch,
            ed_public_key: fixed(&t.ed_public_key)?,
            pq_public_key: Box::new(fixed(&t.pq_public_key)?),
        },
        crypto_era: t.crypto_era,
        key_epoch: t.key_epoch,
        next_nonce: t.next_nonce,
        last_transition: fixed(&t.last_transition)?,
        caller_locks_root: fixed(&t.caller_locks_root)?,
        consumed_exports_root: fixed(&t.consumed_exports_root)?,
    };
    let authorized = if args.len() == 8 {
        match rld_pq_hybrid_interop_candidate::verify_manifest_files(&args[5], &args[6], &args[7])?
        {
            Ok(verified) => {
                if verified.verified_intent.currency_root != initial.policy.currency_root
                    || verified.verified_intent.region_root != initial.policy.region_root
                    || verified.entries.len() != caller.entries.len()
                {
                    return Ok(Err(
                        "authorized manifest differs from independent archive scope/count".into(),
                    ));
                }
                Some(verified)
            }
            Err(error) => return Ok(Err(error)),
        }
    } else {
        None
    };
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&args[3])
        .map_err(|_| "owned public archive directory unavailable")?;
    let m = dir
        .metadata()
        .map_err(|_| "archive directory stat unavailable")?;
    if !m.is_dir() || m.uid() != unsafe { libc::getuid() } || m.mode() & 0o077 != 0 {
        return Err("archive needs owned private directory".into());
    }
    let mut raw = Vec::with_capacity(caller.entries.len());
    let mut observations = Vec::with_capacity(caller.entries.len());
    let mut total = 0usize;
    for (index, item) in caller.entries.into_iter().enumerate() {
        let bytes = entry(&dir, &item.file)?;
        if let Some(manifest) = &authorized {
            let record = &manifest.entries[index];
            let digest: [u8; 64] = Sha512::digest(&bytes).into();
            if record.size_bytes as usize != bytes.len() || record.sha512 != digest {
                return Ok(Err(
                    "complete ordered entry differs from authorized manifest".into(),
                ));
            }
        }
        total = total
            .checked_add(bytes.len())
            .ok_or("archive size overflow")?;
        if total > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES {
            return Err("archive total exceeds bound".into());
        }
        raw.push(bytes);
        observations.push(HybridObservationCandidateV1 {
            current_epoch: item.current_epoch,
            next_nonce: item.next_nonce,
            policy_trust: trust(&item.policy_trust)?,
        });
    }
    Ok(
        verify_hybrid_renewal_archive_candidate(&initial, &raw, &observations, &expected)
            .map_err(|e| e.to_string()),
    )
}
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(Ok(next)) => {
            let authorized = std::env::args().len() == 8;
            let mut result = serde_json::json!({"candidate_only":true,"installed":false,"crypto_era":next.crypto_era,"key_epoch":next.key_epoch,
                "next_nonce":next.next_nonce,"last_transition":hex::encode(next.last_transition),"caller_locks_root":hex::encode(next.caller_locks_root),"consumed_exports_root":hex::encode(next.consumed_exports_root)});
            if authorized {
                result["manifest_authorization_verified"] = serde_json::json!(true);
            }
            println!("{result}");
        }
        Ok(Err(e)) => {
            eprintln!("candidate Core refused: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("candidate archive input unavailable: {e}");
            std::process::exit(2);
        }
    }
}
