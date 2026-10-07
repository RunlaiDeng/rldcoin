//! Fresh RAM-only detached archive-manifest signature candidate. No keys stored,
//! ledger adoption, nonce consumption, transport handshake or old fixture signing.
use ed25519_dalek::Signer as _;
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer as _},
};
use rld_core::{
    hybrid_archive::decode_hybrid_archive_manifest_candidate,
    hybrid_authorization::{
        encode_hybrid_public_envelope_candidate, HybridIntentCandidateV1, HybridProofCandidateV1,
        HybridPurposeV1, HYBRID_CANDIDATE_CONTEXT, HYBRID_CANDIDATE_PROFILE,
    },
};
use sha2::{Digest, Sha512};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
fn output(path: &str, raw: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "fresh public output unavailable")?;
    f.write_all(raw).map_err(|_| "public write unavailable")?;
    f.sync_all().map_err(|_| "public sync failed".into())
}
fn generate(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("expected owned public manifest input, fresh public caller policy and fresh detached envelope paths".into());
    }
    for name in [&args[2], &args[3]] {
        let path = std::path::Path::new(name);
        if path.exists() {
            return Err("output must be fresh".into());
        }
        let parent = path.parent().ok_or("fresh public parent unavailable")?;
        let info =
            std::fs::symlink_metadata(parent).map_err(|_| "fresh public parent unavailable")?;
        if !info.is_dir() || info.uid() != unsafe { libc::getuid() } || info.mode() & 0o077 != 0 {
            return Err("owned private output parent required".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&args[1])
        .map_err(|_| "public manifest unavailable")?;
    let info = file.metadata().map_err(|_| "public stat unavailable")?;
    if !info.is_file()
        || info.uid() != unsafe { libc::getuid() }
        || info.mode() & 0o077 != 0
        || info.len() > 4389
    {
        return Err("owned bounded manifest input required".into());
    }
    let mut manifest = Vec::new();
    file.take(4390)
        .read_to_end(&mut manifest)
        .map_err(|_| "public manifest read failed")?;
    decode_hybrid_archive_manifest_candidate(&manifest)
        .map_err(|_| "public manifest canonical/size/roots invalid")?;
    let mut rng = rand::rngs::OsRng;
    let ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let (public, secret) =
        ml_dsa_87::try_keygen_with_rng(&mut rng).map_err(|_| "fresh RAM key unavailable")?;
    let intent = HybridIntentCandidateV1 {
        currency_root: [1; 32],
        region_root: [2; 32],
        purpose: HybridPurposeV1::ArchiveManifest,
        epoch: 2,
        nonce: 1,
        payload_root: Sha512::digest(&manifest).into(),
    };
    let message = intent.signing_bytes();
    let proof = HybridProofCandidateV1 {
        ed_signature: ed.sign(&message).to_bytes(),
        pq_signature: Box::new(
            secret
                .try_sign_with_rng(&mut rng, &message, HYBRID_CANDIDATE_CONTEXT)
                .map_err(|_| "RAM signing unavailable")?,
        ),
    };
    let policy=serde_json::to_vec(&serde_json::json!({"profile":HYBRID_CANDIDATE_PROFILE,"currency_root":hex::encode(intent.currency_root),"region_root":hex::encode(intent.region_root),"purpose":"ARCHIVE_MANIFEST",
        "valid_from_epoch":1,"valid_until_epoch":8,"ed_public_key":hex::encode(ed.verifying_key().to_bytes()),"pq_public_key":hex::encode(public.into_bytes()),"current_epoch":7,"next_nonce":1,"policy_trust":"CURRENT_AND_TRUSTED"})).map_err(|_|"public caller encode failed")?;
    let envelope = encode_hybrid_public_envelope_candidate(&intent, &proof);
    output(&args[2], &policy)?;
    output(&args[3], &envelope)?;
    println!("fresh RAM-only public archive manifest authorization; no stored keys/consumed nonce/installed state");
    Ok(())
}
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    if let Err(e) = generate(&std::env::args().collect::<Vec<_>>()) {
        eprintln!("candidate fixture unavailable: {e}");
        std::process::exit(1);
    }
}
