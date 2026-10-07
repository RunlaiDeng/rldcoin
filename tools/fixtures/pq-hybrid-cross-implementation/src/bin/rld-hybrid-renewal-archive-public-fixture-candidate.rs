//! Fresh RAM-only no-value renewal signing fixture. Writes public anchor/wire
//! only; no persistent signing keys or adoption. Never reads an old fixture.
use ed25519_dalek::Signer as _;
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer as _},
};
use rld_core::hybrid_authorization::{
    encode_joint_hybrid_renewal_candidate, verify_joint_hybrid_renewal_candidate,
    HybridJointRenewalProofCandidateV1, HybridObservationCandidateV1, HybridPolicyCandidateV1,
    HybridPolicyTrustV1, HybridProofCandidateV1, HybridPurposeV1, HybridRenewalAnchorCandidateV1,
    HybridRenewalCandidateV1, HYBRID_CANDIDATE_CONTEXT, HYBRID_CANDIDATE_PROFILE,
    HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES, HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES,
};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
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
    if args.len() != 5 {
        return Err(
            "expected fresh initial anchor, caller archive metadata, empty directory, finite count"
                .into(),
        );
    }
    let count: usize = args[4].parse().map_err(|_| "count invalid")?;
    if count == 0 || count > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_ENTRIES {
        return Err("count outside finite candidate profile".into());
    }
    let dir = std::path::Path::new(&args[3]);
    if !std::fs::symlink_metadata(dir)
        .map_err(|_| "fresh directory unavailable")?
        .is_dir()
        || std::fs::read_dir(dir)
            .map_err(|_| "fresh directory unavailable")?
            .next()
            .is_some()
        || std::path::Path::new(&args[1]).parent() != Some(dir)
        || std::path::Path::new(&args[2]).parent() != Some(dir)
    {
        return Err("outputs require one empty fresh public fixture directory".into());
    }
    let info = std::fs::symlink_metadata(dir).map_err(|_| "fresh directory unavailable")?;
    if info.uid() != unsafe { libc::getuid() } || info.mode() & 0o077 != 0 {
        return Err("fresh output directory must be owned and private".into());
    }
    let mut rng = rand::rngs::OsRng;
    let mut current_ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let (public, mut current_pq) = ml_dsa_87::try_keygen_with_rng(&mut rng)
        .map_err(|_| "initial RAM fixture key unavailable")?;
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
    let initial = HybridRenewalAnchorCandidateV1 {
        policy: policy(
            1,
            3,
            current_ed.verifying_key().to_bytes(),
            public.into_bytes(),
        ),
        crypto_era: 1,
        key_epoch: 1,
        next_nonce: 1,
        last_transition: [7; 64],
        caller_locks_root: [8; 64],
        consumed_exports_root: [9; 64],
    };
    let mut current = initial.clone();
    let mut entries = Vec::with_capacity(count);
    let mut total = 0usize;
    for index in 0..count {
        let epoch = index as u64 + 2;
        let next_ed = ed25519_dalek::SigningKey::generate(&mut rng);
        let (next_public, next_pq) = ml_dsa_87::try_keygen_with_rng(&mut rng)
            .map_err(|_| "next RAM fixture key unavailable")?;
        let renewal = HybridRenewalCandidateV1 {
            previous_transition: current.last_transition,
            new_crypto_era: current.crypto_era + 1,
            new_key_epoch: current.key_epoch + 1,
            activation_epoch: epoch,
            next_policy: policy(
                epoch,
                epoch + 3,
                next_ed.verifying_key().to_bytes(),
                next_public.into_bytes(),
            ),
        };
        let message = renewal
            .signing_intent(&current)
            .map_err(|_| "joint intent unavailable")?
            .signing_bytes();
        let proof = HybridJointRenewalProofCandidateV1 {
            old: HybridProofCandidateV1 {
                ed_signature: current_ed.sign(&message).to_bytes(),
                pq_signature: Box::new(
                    current_pq
                        .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                        .map_err(|_| "old RAM signing unavailable")?,
                ),
            },
            new: HybridProofCandidateV1 {
                ed_signature: next_ed.sign(&message).to_bytes(),
                pq_signature: Box::new(
                    next_pq
                        .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                        .map_err(|_| "new RAM signing unavailable")?,
                ),
            },
        };
        let observation = HybridObservationCandidateV1 {
            current_epoch: epoch,
            next_nonce: current.next_nonce,
            policy_trust: HybridPolicyTrustV1::CurrentAndTrusted,
        };
        let raw = encode_joint_hybrid_renewal_candidate(&renewal, &proof)
            .map_err(|_| "public renewal encode failed")?;
        total = total
            .checked_add(raw.len())
            .ok_or("public archive size overflow")?;
        if total > HYBRID_RENEWAL_ARCHIVE_CANDIDATE_MAX_TOTAL_BYTES {
            return Err("public archive exceeds total bound".into());
        }
        let filename = format!("renewal-{index:03}-public.json");
        output(
            dir.join(&filename)
                .to_str()
                .ok_or("public filename unavailable")?,
            &raw,
        )?;
        entries.push(serde_json::json!({"file":filename,"current_epoch":epoch,"next_nonce":current.next_nonce,"policy_trust":"CURRENT_AND_TRUSTED"}));

        current = verify_joint_hybrid_renewal_candidate(&current, &renewal, &proof, observation)
            .map_err(|_| "fresh fixture joint verification failed")?;
        current_ed = next_ed;
        current_pq = next_pq;
    }
    let p = &initial.policy;
    let anchor=serde_json::to_vec(&serde_json::json!({
        "profile":p.profile,"currency_root":hex::encode(p.currency_root),"region_root":hex::encode(p.region_root),
        "purpose":p.purpose,"valid_from_epoch":p.valid_from_epoch,"valid_until_epoch":p.valid_until_epoch,
        "ed_public_key":hex::encode(p.ed_public_key),"pq_public_key":hex::encode(p.pq_public_key.as_ref()),
        "crypto_era":initial.crypto_era,"key_epoch":initial.key_epoch,"next_nonce":initial.next_nonce,
        "last_transition":hex::encode(initial.last_transition),"caller_locks_root":hex::encode(initial.caller_locks_root),
        "consumed_exports_root":hex::encode(initial.consumed_exports_root),"current_epoch":2,"policy_trust":"CURRENT_AND_TRUSTED",
    })).map_err(|_| "public initial anchor encode failed")?;
    let caller = serde_json::to_vec(
        &serde_json::json!({"profile":"RLDCOIN-HYBRID-RENEWAL-ARCHIVE-CALLER-CANDIDATE-V1",
        "expected_latest_transition":hex::encode(current.last_transition),"entries":entries}),
    )
    .map_err(|_| "public caller metadata encode failed")?;
    if anchor.len() > 8192 || caller.len() > 32768 {
        return Err("public caller input exceeds bounds".into());
    }
    output(&args[1], &anchor)?;
    output(&args[2], &caller)?;
    println!("fresh RAM-only archive entries={count} complete bytes={total}; caller context same controller; no stored signing keys or installed state");
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
