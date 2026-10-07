//! Offline complete append archive verification, never installed state.
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    let a = std::env::args().collect::<Vec<_>>();
    if a.len() != 4 {
        eprintln!(
            "expected separate policy, independent caller anchors/observations, complete archive"
        );
        std::process::exit(2);
    }
    match rld_pq_hybrid_interop_candidate::append_archive::verify_files(&a[1], &a[2], &a[3]) {
        Ok(Ok(v)) => println!(
            "{}",
            serde_json::json!({"candidate_only":true,"installed":false,"nonce_consumed":false,"current_root":hex::encode(v.current_root),"key_count":v.key_count,"next_nonce":v.next_nonce,"archive_head":hex::encode(v.archive_head),"caller_locks_root":hex::encode(v.caller_locks_root)})
        ),
        Ok(Err(e)) => {
            eprintln!("Core candidate refused: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("public inputs unavailable: {e}");
            std::process::exit(2);
        }
    }
}
