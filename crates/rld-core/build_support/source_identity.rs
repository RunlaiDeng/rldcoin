use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub const FORMAT: &str = "RLD-EARTH-IMPLEMENTATION-SOURCE";
const MAX_FILES: usize = 8192;
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Entry {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub format: &'static str,
    pub commitment: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub files: Vec<Entry>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn ignored(name: &str) -> bool {
    name.starts_with('.')
        || matches!(name, "target" | "node_modules" | "__pycache__")
        || name.ends_with(".pyc")
}
fn collect(
    root: &Path,
    path: &Path,
    files: &mut Vec<PathBuf>,
    watched: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(invalid("symlink in implementation source set"));
    }
    watched.push(path.to_path_buf());
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("non-UTF8 source name"))?;
            if name.contains('\\') || name.chars().any(char::is_control) {
                return Err(invalid("unsafe implementation source name"));
            }
            if !ignored(name) {
                collect(root, &entry.path(), files, watched)?;
            }
        }
    } else if meta.is_file() {
        if files.len() >= MAX_FILES || meta.len() > MAX_FILE_BYTES {
            return Err(invalid("implementation source limit exceeded"));
        }
        path.strip_prefix(root)
            .map_err(|_| invalid("source outside root"))?;
        files.push(path.to_path_buf());
    } else {
        return Err(invalid("non-regular implementation source"));
    }
    Ok(())
}

/// Exact named source set, not compiler/environment attestation or authorization.
pub fn capture(root: &Path) -> io::Result<(Manifest, Vec<PathBuf>)> {
    let mut paths = Vec::new();
    let mut watched = Vec::new();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates",
        "vectors",
        "spec",
        "docs/spec",
    ] {
        collect(root, &root.join(name), &mut paths, &mut watched)?;
    }
    paths.sort_by_key(|p| {
        p.strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
    });
    let mut digest = Sha256::new();
    digest.update(FORMAT.as_bytes());
    digest.update([0]);
    digest.update((paths.len() as u32).to_be_bytes());
    let mut entries = Vec::new();
    let mut total = 0u64;
    for path in paths {
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 source path"))?
            .replace('\\', "/");
        if name.len() > 4096 {
            return Err(invalid("implementation source path too long"));
        }
        let mut input = fs::File::open(&path)?;
        let mut bytes = 0u64;
        let mut file_hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            bytes = bytes
                .checked_add(n as u64)
                .filter(|v| *v <= MAX_FILE_BYTES)
                .ok_or_else(|| invalid("implementation source file too large"))?;
            total = total
                .checked_add(n as u64)
                .filter(|v| *v <= MAX_TOTAL_BYTES)
                .ok_or_else(|| invalid("implementation source total too large"))?;
            file_hash.update(&buffer[..n]);
        }
        let hash = file_hash.finalize();
        digest.update((name.len() as u32).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(bytes.to_be_bytes());
        digest.update(hash);
        entries.push(Entry {
            path: name,
            size_bytes: bytes,
            sha256: format!("{hash:x}"),
        });
    }
    Ok((
        Manifest {
            format: FORMAT,
            commitment: format!("{:x}", digest.finalize()),
            file_count: entries.len(),
            total_bytes: total,
            files: entries,
        },
        watched,
    ))
}
