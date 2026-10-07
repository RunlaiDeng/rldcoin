//! Verification-only complete renewal adapter. Independent caller anchor is
//! mandatory, never learned from TLS or the new policy. Does not install state.
use rld_core::hybrid_authorization::{
    decode_joint_hybrid_renewal_candidate, verify_joint_hybrid_renewal_candidate,
    HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridPolicyTrustV1, HybridPurposeV1,
    HybridRenewalAnchorCandidateV1, HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
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
fn bounded(path: &str, max: usize) -> Result<Vec<u8>, String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "bounded public input unavailable")?;
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
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("anchor needs exact canonical hex".into());
    }
    hex::decode(s)
        .map_err(|_| "anchor hex invalid")?
        .try_into()
        .map_err(|_| "anchor size invalid".into())
}
fn verify(args: &[String]) -> Result<Result<HybridRenewalAnchorCandidateV1, String>, String> {
    if args.len() != 3 {
        return Err("expected separately trusted anchor and full public renewal".into());
    }
    let t: TrustedAnchor = serde_json::from_slice(&bounded(&args[1], 8192)?)
        .map_err(|_| "anchor malformed/duplicate/unknown")?;
    let observation = HybridObservationCandidateV1 {
        current_epoch: t.current_epoch,
        next_nonce: t.next_nonce,
        policy_trust: match t.policy_trust.as_str() {
            "CURRENT_AND_TRUSTED" => HybridPolicyTrustV1::CurrentAndTrusted,
            "BROKEN" => HybridPolicyTrustV1::Broken,
            "REVOKED" => HybridPolicyTrustV1::Revoked,
            "UNAVAILABLE" => HybridPolicyTrustV1::Unavailable,
            _ => return Err("unknown independent trust observation".into()),
        },
    };
    let anchor = HybridRenewalAnchorCandidateV1 {
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
    let raw = bounded(&args[2], HYBRID_RENEWAL_CANDIDATE_MAX_PUBLIC_WIRE_BYTES)?;
    let result = decode_joint_hybrid_renewal_candidate(&raw)
        .and_then(|(renewal, proof)| {
            verify_joint_hybrid_renewal_candidate(&anchor, &renewal, &proof, observation)
        })
        .map_err(|e| e.to_string());
    Ok(result)
}
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(Ok(next)) => println!(
            "{}",
            serde_json::json!({"candidate_only":true,"installed":false,"crypto_era":next.crypto_era,
            "key_epoch":next.key_epoch,"next_nonce":next.next_nonce,"last_transition":hex::encode(next.last_transition),
            "caller_locks_root":hex::encode(next.caller_locks_root),"consumed_exports_root":hex::encode(next.consumed_exports_root)})
        ),
        Ok(Err(e)) => {
            eprintln!("candidate Core refused: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("candidate Core input unavailable: {e}");
            std::process::exit(2);
        }
    }
}
