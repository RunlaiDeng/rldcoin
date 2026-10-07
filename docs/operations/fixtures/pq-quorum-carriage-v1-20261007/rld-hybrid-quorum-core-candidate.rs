//! Public-only adapter to the actual fixed-threshold Core candidate.
use rld_core::{
    hybrid_authorization::{
        HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridPolicyTrustV1, HybridPurposeV1,
    },
    hybrid_quorum::{
        decode_hybrid_quorum_candidate, verify_hybrid_quorum_candidate,
        HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES, HYBRID_QUORUM_CANDIDATE_PROFILE,
    },
};
use serde::Deserialize;
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roster {
    members: [Member; 4],
    profile: String,
}

fn bounded(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "bounded public input unavailable")?;
    let metadata = file.metadata().map_err(|_| "input stat unavailable")?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "bounded input read failed")?;
    if bytes.len() > maximum {
        return Err("input grew beyond bound".into());
    }
    Ok(bytes)
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("policy requires exact lowercase hex".into());
    }
    hex::decode(value)
        .map_err(|_| "policy malformed".to_string())?
        .try_into()
        .map_err(|_| "policy length differs".into())
}

fn verify(args: &[String]) -> Result<Result<(), String>, String> {
    if args.len() != 3 {
        return Err("expected independently trusted roster then public quorum".into());
    }
    let roster: Roster = serde_json::from_slice(&bounded(&args[1], 24576)?)
        .map_err(|_| "trusted roster malformed, duplicate or unknown field")?;
    if roster.profile != HYBRID_QUORUM_CANDIDATE_PROFILE {
        return Err("unknown trusted quorum profile".into());
    }
    let mut policies = Vec::with_capacity(4);
    let mut observations = Vec::with_capacity(4);
    for member in roster.members {
        policies.push(HybridPolicyCandidateV1 {
            profile: member.profile,
            currency_root: fixed(&member.currency_root)?,
            region_root: fixed(&member.region_root)?,
            purpose: member.purpose,
            valid_from_epoch: member.valid_from_epoch,
            valid_until_epoch: member.valid_until_epoch,
            ed_public_key: fixed(&member.ed_public_key)?,
            pq_public_key: Box::new(fixed(&member.pq_public_key)?),
        });
        observations.push(HybridObservationCandidateV1 {
            current_epoch: member.current_epoch,
            next_nonce: member.next_nonce,
            policy_trust: match member.policy_trust.as_str() {
                "CURRENT_AND_TRUSTED" => HybridPolicyTrustV1::CurrentAndTrusted,
                "REVOKED" => HybridPolicyTrustV1::Revoked,
                "BROKEN" => HybridPolicyTrustV1::Broken,
                "UNAVAILABLE" => HybridPolicyTrustV1::Unavailable,
                _ => return Err("unknown independently supplied trust".into()),
            },
        });
    }
    let policies = policies.try_into().map_err(|_| "roster count differs")?;
    let observations = observations
        .try_into()
        .map_err(|_| "observation count differs")?;
    let bytes = bounded(&args[2], HYBRID_QUORUM_CANDIDATE_MAX_PUBLIC_WIRE_BYTES)?;
    Ok(decode_hybrid_quorum_candidate(&bytes)
        .and_then(|quorum| verify_hybrid_quorum_candidate(&policies, &quorum, &observations))
        .map_err(|error| error.to_string()))
}

fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(Ok(())) => println!(
            "candidate Core three distinct dual signatures verified; no finality or state granted"
        ),
        Ok(Err(error)) => {
            eprintln!("candidate Core quorum refused: {error}");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate Core quorum input unavailable: {error}");
            std::process::exit(2);
        }
    }
}
