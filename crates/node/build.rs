//! Refuse compilation against a stale native/proof source binding.
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn inputs(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
        root.join("crates/protocol/Cargo.toml"),
        root.join("methods/Cargo.toml"),
        root.join("methods/build.rs"),
        root.join("methods/guest/Cargo.toml"),
        root.join("methods/guest/Cargo.lock"),
    ];
    fn walk(path: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).expect("source inventory") {
            let entry = entry.expect("source entry");
            if entry.file_type().expect("source type").is_dir() {
                walk(&entry.path(), out);
            } else if entry.path().extension().is_some_and(|e| e == "rs") {
                out.push(entry.path());
            }
        }
    }
    for path in ["crates/protocol/src", "methods/src", "methods/guest/src"] {
        walk(&root.join(path), &mut files);
    }
    // Match the pinning tool's canonical UTF-8 slash-delimited path order,
    // including files beside same-named subdirectories (state.rs/state/).
    files.sort_by_key(|p| {
        p.strip_prefix(root)
            .expect("source path")
            .to_str()
            .expect("source UTF8")
            .replace('\\', "/")
    });
    files
}
fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let profile = root.join("spec/EXECUTABLE_PROFILE.json");
    println!("cargo:rerun-if-changed={}", profile.display());
    let mut digest = Sha256::new();
    for path in inputs(&root) {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .expect("source UTF8")
            .replace('\\', "/");
        let bytes = fs::read(&path).expect("source bytes");
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    let actual = format!("{:x}", digest.finalize());
    let binding: serde_json::Value = serde_json::from_slice(&fs::read(profile).expect(
        "pinned executable profile; build real prover and run tools/pin-executable-profile.py",
    ))
    .expect("executable profile JSON");
    assert_eq!(
        binding["format"], "RLD-EXECUTABLE-PROFILE-1",
        "executable profile format"
    );
    assert_eq!(
        binding["source_digest"].as_str(),
        Some(actual.as_str()),
        "native/proof source binding is stale: build real rld-prover, then run tools/pin-executable-profile.py; never reuse old monetary state"
    );
    println!("cargo:rustc-env=RLD_EXECUTABLE_SOURCE_DIGEST={actual}");
}
