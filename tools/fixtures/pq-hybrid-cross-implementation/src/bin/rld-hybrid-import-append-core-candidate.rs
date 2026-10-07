//! Offline dual-authorized append verification, with separately trusted inputs.
fn main() {
    println!(
        "Core implementation source: {}",
        rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    let a = std::env::args().collect::<Vec<_>>();
    if a.len() != 6 {
        eprintln!("expected separate policy, current root, query, proof, envelope");
        std::process::exit(2);
    }
    match rld_pq_hybrid_interop_candidate::verify_import_append_files(
        &a[1], &a[2], &a[3], &a[4], &a[5],
    ) {
        Ok(Ok(v)) => println!(
            "{}",
            serde_json::json!({"candidate_only":true,"installed":false,"nonce_consumed":false,
            "previous_root":hex::encode(v.append.previous_root),"new_root":hex::encode(v.append.new_root),
            "payload_root":hex::encode(v.append.payload_root),"previous_key_count":v.append.previous_key_count,"new_key_count":v.append.new_key_count})
        ),
        Ok(Err(e)) => {
            eprintln!("candidate Core refused: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("public input unavailable: {e}");
            std::process::exit(2);
        }
    }
}
