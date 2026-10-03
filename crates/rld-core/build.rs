#[path = "build_support/source_identity.rs"]
mod source_identity;

fn main() {
    let crate_dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = crate_dir.parent().unwrap().parent().unwrap();
    let (manifest, watched) =
        source_identity::capture(root).expect("bounded implementation source capture failed");
    for path in watched {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let encoded = serde_json::to_vec(&manifest).unwrap();
    assert!(encoded.len() < 4 * 1024 * 1024, "source manifest ceiling");
    std::fs::write(output.join("implementation-source.json"), encoded).unwrap();
    // A Rust source constant avoids accepting an inherited environment override.
    std::fs::write(
        output.join("implementation-source.rs"),
        format!(
            "pub const IMPLEMENTATION_SOURCE_COMMITMENT: &str = {:?};\n",
            manifest.commitment
        ),
    )
    .unwrap();
}
