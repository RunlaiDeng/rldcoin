//! Fresh RAM-only no-value renewal signing fixture. Writes public anchor/wire
//! only; no persistent signing keys or adoption. Never reads an old fixture.
use ed25519_dalek::Signer as _;
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer as _},
};
use rld_core::hybrid_authorization::{
    encode_joint_hybrid_renewal_candidate, HybridJointRenewalProofCandidateV1,
    HybridPolicyCandidateV1, HybridProofCandidateV1, HybridPurposeV1,
    HybridRenewalAnchorCandidateV1, HybridRenewalCandidateV1, HYBRID_CANDIDATE_CONTEXT,
    HYBRID_CANDIDATE_PROFILE,
};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
fn output(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "fresh public output unavailable")?;
    f.write_all(bytes).map_err(|_| "public write failed")?;
    f.sync_all().map_err(|_| "public sync failed".into())
}
fn generate(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("expected fresh public anchor and complete renewal paths".into());
    }
    let mut rng = rand::rngs::OsRng;
    let old_ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let new_ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let (old_pub, old_sec) =
        ml_dsa_87::try_keygen_with_rng(&mut rng).map_err(|_| "old RAM fixture key unavailable")?;
    let (new_pub, new_sec) =
        ml_dsa_87::try_keygen_with_rng(&mut rng).map_err(|_| "new RAM fixture key unavailable")?;
    let policy = |from, until, ed, pq| HybridPolicyCandidateV1 {
        profile: HYBRID_CANDIDATE_PROFILE.into(),
        currency_root: [1; 32],
        region_root: [2; 32],
        purpose: HybridPurposeV1::Renewal,
        valid_from_epoch: from,
        valid_until_epoch: until,
        ed_public_key: ed,
        pq_public_key: Box::new(pq),
    };
    let anchor = HybridRenewalAnchorCandidateV1 {
        policy: policy(
            1,
            3,
            old_ed.verifying_key().to_bytes(),
            old_pub.into_bytes(),
        ),
        crypto_era: 1,
        key_epoch: 1,
        next_nonce: 1,
        last_transition: [7; 64],
        caller_locks_root: [8; 64],
        consumed_exports_root: [9; 64],
    };
    let renewal = HybridRenewalCandidateV1 {
        previous_transition: anchor.last_transition,
        new_crypto_era: 2,
        new_key_epoch: 2,
        activation_epoch: 2,
        next_policy: policy(
            2,
            5,
            new_ed.verifying_key().to_bytes(),
            new_pub.into_bytes(),
        ),
    };
    let message = renewal
        .signing_intent(&anchor)
        .map_err(|_| "candidate intent unavailable")?
        .signing_bytes();
    let proof = HybridJointRenewalProofCandidateV1 {
        old: HybridProofCandidateV1 {
            ed_signature: old_ed.sign(&message).to_bytes(),
            pq_signature: Box::new(
                old_sec
                    .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                    .map_err(|_| "old RAM signing unavailable")?,
            ),
        },
        new: HybridProofCandidateV1 {
            ed_signature: new_ed.sign(&message).to_bytes(),
            pq_signature: Box::new(
                new_sec
                    .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                    .map_err(|_| "new RAM signing unavailable")?,
            ),
        },
    };
    let p = &anchor.policy;
    let public_anchor=serde_json::to_vec(&serde_json::json!({
        "profile":p.profile,"currency_root":hex::encode(p.currency_root),"region_root":hex::encode(p.region_root),
        "purpose":p.purpose,"valid_from_epoch":p.valid_from_epoch,"valid_until_epoch":p.valid_until_epoch,
        "ed_public_key":hex::encode(p.ed_public_key),"pq_public_key":hex::encode(p.pq_public_key.as_ref()),
        "crypto_era":anchor.crypto_era,"key_epoch":anchor.key_epoch,"next_nonce":anchor.next_nonce,
        "last_transition":hex::encode(anchor.last_transition),"caller_locks_root":hex::encode(anchor.caller_locks_root),
        "consumed_exports_root":hex::encode(anchor.consumed_exports_root),"current_epoch":2,"policy_trust":"CURRENT_AND_TRUSTED",
    })).map_err(|_| "public anchor encode failed")?;
    if public_anchor.len() > 8192 {
        return Err("public anchor exceeds bound".into());
    }
    let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof)
        .map_err(|_| "complete public renewal encode failed")?;
    output(&args[1], &public_anchor)?;
    output(&args[2], &raw)?;
    println!("fresh RAM-only complete public renewal bytes={}; no installed policy or stored signing keys",raw.len());
    Ok(())
}
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    if let Err(e) = generate(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("public fixture unavailable: {e}");
        std::process::exit(1);
    }
}
