//! Fresh RAM-only signing fixture; writes only public keys/envelopes. No money,
//! ledger, installed policy, old fixture, persistent key or production signing.
use ed25519_dalek::Signer as _;
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer as _},
};
use rld_core::{
    hybrid_authorization::{
        HybridIntentCandidateV1, HybridProofCandidateV1, HybridPurposeV1, HYBRID_CANDIDATE_CONTEXT,
        HYBRID_CANDIDATE_PROFILE,
    },
    hybrid_quorum::{
        encode_hybrid_quorum_candidate, HybridMemberProofCandidateV1, HybridQuorumCandidateV1,
        HYBRID_QUORUM_CANDIDATE_PROFILE,
    },
};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

fn fresh_public_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "fresh public output unavailable")?;
    file.write_all(bytes).map_err(|_| "public write failed")?;
    file.sync_all().map_err(|_| "public sync failed".into())
}

fn generate(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("expected fresh public roster and fresh public quorum paths".into());
    }
    let intent = HybridIntentCandidateV1 {
        currency_root: [1; 32],
        region_root: [2; 32],
        purpose: HybridPurposeV1::Finality,
        epoch: 2,
        nonce: 1,
        payload_root: [3; 64],
    };
    let message = intent.signing_bytes();
    let mut members = Vec::with_capacity(4);
    let mut proofs = Vec::with_capacity(3);
    for index in 0..4 {
        let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let (public, secret) = ml_dsa_87::try_keygen_with_rng(&mut rand::rngs::OsRng)
            .map_err(|_| "fresh RAM fixture key failed")?;
        if index < 3 {
            proofs.push(HybridMemberProofCandidateV1 {
                member: index,
                proof: HybridProofCandidateV1 {
                    ed_signature: ed.sign(&message).to_bytes(),
                    pq_signature: Box::new(
                        secret
                            .try_sign_with_rng(
                                &mut rand::rngs::OsRng,
                                &message,
                                HYBRID_CANDIDATE_CONTEXT,
                            )
                            .map_err(|_| "fresh RAM fixture signing failed")?,
                    ),
                },
            });
        }
        members.push(serde_json::json!({
            "profile": HYBRID_CANDIDATE_PROFILE, "currency_root": hex::encode(intent.currency_root),
            "region_root": hex::encode(intent.region_root), "purpose": "FINALITY",
            "valid_from_epoch": 1, "valid_until_epoch": 9, "ed_public_key": hex::encode(ed.verifying_key().to_bytes()),
            "pq_public_key": hex::encode(public.into_bytes()), "current_epoch": 2, "next_nonce": 1,
            "policy_trust": "CURRENT_AND_TRUSTED",
        }));
    }
    let roster = serde_json::to_vec(
        &serde_json::json!({"members": members, "profile": HYBRID_QUORUM_CANDIDATE_PROFILE}),
    )
    .map_err(|_| "public roster encoding failed")?;
    let quorum = encode_hybrid_quorum_candidate(&HybridQuorumCandidateV1 {
        intent,
        members: proofs,
    })
    .map_err(|_| "public quorum encoding failed")?;
    if roster.len() > 24576 {
        return Err("public roster exceeds bound".into());
    }
    fresh_public_file(&args[1], &roster)?;
    fresh_public_file(&args[2], &quorum)?;
    println!(
        "fresh RAM-only candidate fixture; public quorum bytes={}, no stored signing keys",
        quorum.len()
    );
    Ok(())
}

fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    if let Err(error) = generate(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("public fixture refused: {error}");
        std::process::exit(1);
    }
}
