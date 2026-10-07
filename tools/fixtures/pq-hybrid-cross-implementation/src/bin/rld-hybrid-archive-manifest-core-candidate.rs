//! Offline manifest verification-only file entry; policy is independently trusted.
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        eprintln!("expected separate trusted policy/observation, public manifest and detached public envelope");
        std::process::exit(2);
    }
    match rld_pq_hybrid_interop_candidate::verify_manifest_files(&args[1], &args[2], &args[3]) {
        Ok(Ok(v)) => println!(
            "{}",
            serde_json::json!({"candidate_only":true,"installed":false,"nonce_consumed":false,
            "manifest_sha512":hex::encode(v.manifest_root),"complete_entries":v.entries.len(),"total_entry_bytes":v.total_bytes,
            "verified_epoch":v.verified_intent.epoch,"verified_nonce":v.verified_intent.nonce,"purpose":"ARCHIVE_MANIFEST"})
        ),
        Ok(Err(e)) => {
            eprintln!("candidate Core refused: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("candidate public input unavailable: {e}");
            std::process::exit(2);
        }
    }
}
