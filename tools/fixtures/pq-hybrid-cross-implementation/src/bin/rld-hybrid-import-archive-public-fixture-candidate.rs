//! Fresh RAM-only public no-value append archive fixture; no private keys stored.
use ed25519_dalek::Signer as _;
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Signer as _},
};
use rld_core::{
    hybrid_authorization::{
        encode_hybrid_public_envelope_candidate, HybridIntentCandidateV1, HybridProofCandidateV1,
        HybridPurposeV1, HYBRID_CANDIDATE_CONTEXT, HYBRID_CANDIDATE_PROFILE,
    },
    hybrid_permanent_import::prepare_permanent_import_append_candidate,
};
use rld_pq_hybrid_interop_candidate::{
    append_archive::DOMAIN, read_owned_public_candidate as read,
};
use sha2::{Digest, Sha512};
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};
fn output(path: &str, raw: &[u8]) -> Result<(), String> {
    let p = std::path::Path::new(path);
    let info = std::fs::symlink_metadata(p.parent().ok_or("output parent missing")?)
        .map_err(|_| "output parent unavailable")?;
    if !info.is_dir() || info.uid() != unsafe { libc::getuid() } || info.mode() & 0o077 != 0 {
        return Err("owned private output parent required".into());
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|_| "fresh public output required")?;
    f.write_all(raw).map_err(|_| "write unavailable")?;
    f.sync_all().map_err(|_| "public sync unavailable".into())
}
fn generate(a: &[String]) -> Result<(), String> {
    if a.len() != 5 {
        return Err(
            "expected public unsigned proof plan, fresh policy, fresh caller and fresh archive"
                .into(),
        );
    }
    let plan: serde_json::Value =
        serde_json::from_slice(&read(&a[1], 4194304)?).map_err(|_| "public plan malformed")?;
    let list = plan.as_array().ok_or("public plan array required")?;
    if list.is_empty() || list.len() > 64 {
        return Err("public plan count differs".into());
    }
    let mut scope = [1; 64];
    scope[32..].fill(2);
    let mut root: [u8; 64] = Sha512::digest(
        [
            b"RLD-PERMANENT-IMPORT-INDEX-CANDIDATE-V1\0".as_slice(),
            &scope,
            b"E",
        ]
        .concat(),
    )
    .into();
    let initial = serde_json::json!({"current_root":hex::encode(root),"key_count":0,"next_nonce":1,"archive_head":hex::encode([4;64]),"caller_locks_root":hex::encode([5;64])});
    let mut head = [4; 64];
    let mut nonce = 1u64;
    let mut count = 0u32;
    let mut observations = Vec::new();
    let mut rng = rand::rngs::OsRng;
    let ed = ed25519_dalek::SigningKey::generate(&mut rng);
    let (pq, secret) =
        ml_dsa_87::try_keygen_with_rng(&mut rng).map_err(|_| "fresh RAM key unavailable")?;
    let mut wire = DOMAIN.to_vec();
    wire.extend_from_slice(&(list.len() as u16).to_be_bytes());
    for item in list {
        let query: [u8; 32] = hex::decode(item["query"].as_str().ok_or("query required")?)
            .map_err(|_| "query hex malformed")?
            .try_into()
            .map_err(|_| "query size differs")?;
        let proof = hex::decode(item["proof"].as_str().ok_or("proof required")?)
            .map_err(|_| "proof hex malformed")?;
        let append = prepare_permanent_import_append_candidate(&scope, &root, &query, &proof)
            .map_err(|_| "public plan append refused")?;
        if append.previous_key_count != count {
            return Err("public plan count differs".into());
        }
        let intent = HybridIntentCandidateV1 {
            currency_root: [1; 32],
            region_root: [2; 32],
            purpose: HybridPurposeV1::PermanentImportAppend,
            epoch: 2,
            nonce,
            payload_root: append.payload_root,
        };
        let msg = intent.signing_bytes();
        let signatures = HybridProofCandidateV1 {
            ed_signature: ed.sign(&msg).to_bytes(),
            pq_signature: Box::new(
                secret
                    .try_sign_with_rng(&mut rng, &msg, HYBRID_CANDIDATE_CONTEXT)
                    .map_err(|_| "RAM signing unavailable")?,
            ),
        };
        let envelope = encode_hybrid_public_envelope_candidate(&intent, &signatures);
        let mut h = Sha512::new();
        h.update(b"RLD-PERMANENT-IMPORT-APPEND-ARCHIVE-HEAD-CANDIDATE-V1\0");
        h.update(scope);
        h.update(head);
        h.update([5; 64]);
        h.update(nonce.to_be_bytes());
        h.update(2u64.to_be_bytes());
        h.update(append.payload_root);
        h.update(Sha512::digest(&envelope));
        head = h.finalize().into();
        wire.extend_from_slice(&query);
        wire.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        wire.extend_from_slice(&proof);
        wire.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        wire.extend_from_slice(&envelope);
        root = append.new_root;
        count = append.new_key_count;
        observations.push(serde_json::json!({"current_epoch":7,"next_nonce":nonce,"policy_trust":"CURRENT_AND_TRUSTED"}));
        nonce += 1;
    }
    let policy = serde_json::json!({"profile":HYBRID_CANDIDATE_PROFILE,"currency_root":"01".repeat(32),"region_root":"02".repeat(32),"purpose":"PERMANENT_IMPORT_APPEND","valid_from_epoch":1,"valid_until_epoch":8,"ed_public_key":hex::encode(ed.verifying_key().to_bytes()),"pq_public_key":hex::encode(pq.into_bytes()),"current_epoch":7,"next_nonce":1,"policy_trust":"CURRENT_AND_TRUSTED"});
    let caller = serde_json::json!({"initial":initial,"latest":{"current_root":hex::encode(root),"key_count":count,"next_nonce":nonce,"archive_head":hex::encode(head),"caller_locks_root":hex::encode([5;64])},"observations":observations});
    output(
        &a[2],
        &serde_json::to_vec(&policy).map_err(|_| "public policy encode unavailable")?,
    )?;
    output(
        &a[3],
        &serde_json::to_vec(&caller).map_err(|_| "public caller encode unavailable")?,
    )?;
    output(&a[4], &wire)?;
    println!("fresh public RAM-only no-value append archive; no installed state or stored keys");
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
