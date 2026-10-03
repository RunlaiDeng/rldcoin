use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(!meta.file_type().is_symlink());
        if meta.is_dir() {
            collect(&path, files)
        } else {
            files.push(path)
        }
    }
}
fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let mut files = vec![
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("build.rs"),
    ];
    collect(&root.join("src"), &mut files);
    files.sort();
    let mut hash = Sha256::new();
    hash.update(b"RLD-REGIONAL-CANDIDATE-SOURCE-V1\0");
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.strip_prefix(&root).unwrap().to_str().unwrap();
        let bytes = fs::read(&path).unwrap();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    println!(
        "cargo:rustc-env=RLD_REGIONAL_SOURCE={}",
        hex::encode(hash.finalize())
    );
}
