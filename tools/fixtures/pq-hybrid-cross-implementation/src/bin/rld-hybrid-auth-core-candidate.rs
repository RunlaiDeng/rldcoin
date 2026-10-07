//! Verification-only Core adapter. Local policy/observation are caller inputs,
//! supplied independently of TLS/public wire, never discovered from the sender.
use rld_core::hybrid_authorization::{
    decode_hybrid_public_envelope_candidate, verify_hybrid_authorization_candidate,
    HybridObservationCandidateV1, HybridPolicyCandidateV1, HybridPolicyTrustV1, HybridPurposeV1,
    HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES,
};
use serde::Deserialize;
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

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
        return Err("trusted policy requires exact lowercase hex".into());
    }
    hex::decode(value)
        .map_err(|_| "policy hex malformed".to_string())?
        .try_into()
        .map_err(|_| "policy length differs".into())
}

fn verify(args: &[String]) -> Result<Result<(), String>, String> {
    if args.len() != 3 {
        return Err("expected separately trusted local policy and public envelope".into());
    }
    let trusted: TrustedInput = serde_json::from_slice(&bounded(&args[1], 8192)?)
        .map_err(|_| "trusted input malformed, duplicate or unknown field")?;
    let observation = HybridObservationCandidateV1 {
        current_epoch: trusted.current_epoch,
        next_nonce: trusted.next_nonce,
        policy_trust: match trusted.policy_trust.as_str() {
            "CURRENT_AND_TRUSTED" => HybridPolicyTrustV1::CurrentAndTrusted,
            "REVOKED" => HybridPolicyTrustV1::Revoked,
            "BROKEN" => HybridPolicyTrustV1::Broken,
            "UNAVAILABLE" => HybridPolicyTrustV1::Unavailable,
            _ => return Err("unknown caller trust observation".into()),
        },
    };
    let policy = HybridPolicyCandidateV1 {
        profile: trusted.profile,
        currency_root: fixed(&trusted.currency_root)?,
        region_root: fixed(&trusted.region_root)?,
        purpose: trusted.purpose,
        valid_from_epoch: trusted.valid_from_epoch,
        valid_until_epoch: trusted.valid_until_epoch,
        ed_public_key: fixed(&trusted.ed_public_key)?,
        pq_public_key: Box::new(fixed(&trusted.pq_public_key)?),
    };
    let raw = bounded(&args[2], HYBRID_CANDIDATE_MAX_PUBLIC_WIRE_BYTES)?;
    let result = decode_hybrid_public_envelope_candidate(&raw)
        .and_then(|(intent, proof)| {
            verify_hybrid_authorization_candidate(&policy, &intent, &proof, observation)
        })
        .map_err(|error| error.to_string());
    Ok(result)
}

fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(Ok(())) => {
            println!("candidate Core dual verification passed; no state or authority granted")
        }
        Ok(Err(error)) => {
            eprintln!("candidate Core refused: {error}");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate Core input unavailable: {error}");
            std::process::exit(2);
        }
    }
}
