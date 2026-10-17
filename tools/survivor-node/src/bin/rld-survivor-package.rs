//! Deterministic allowlisted no-value distribution; never scans private state.
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
fn octal(field: &mut [u8], n: u64) -> Result<(), String> {
    let text = format!("{:0width$o}", n, width = field.len() - 1);
    if text.len() != field.len() - 1 {
        return Err("tar numeric bound".into());
    }
    field[..text.len()].copy_from_slice(text.as_bytes());
    field[text.len()] = 0;
    Ok(())
}
fn append(out: &mut File, name: &str, raw: &[u8], executable: bool) -> Result<(), String> {
    if name.len() > 100 {
        return Err("archive name bound".into());
    }
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], if executable { 0o755 } else { 0o644 })?;
    octal(&mut h[108..116], 0)?;
    octal(&mut h[116..124], 0)?;
    octal(&mut h[124..136], raw.len() as u64)?;
    octal(&mut h[136..148], 0)?;
    h[148..156].fill(b' ');
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|n| *n as u64).sum();
    let c = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(c.as_bytes());
    out.write_all(&h)
        .and_then(|_| out.write_all(raw))
        .map_err(|e| e.to_string())?;
    let pad = (512 - raw.len() % 512) % 512;
    out.write_all(&vec![0; pad]).map_err(|e| e.to_string())
}
fn read(path: &Path) -> Result<Vec<u8>, String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_file() || m.len() > 64 * 1024 * 1024 {
        return Err(format!(
            "allowlisted regular-file size bound: {} ({} bytes)",
            path.display(),
            m.len()
        ));
    }
    fs::read(path).map_err(|e| e.to_string())
}
fn run() -> Result<(), String> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() != 4 {
        return Err(
            "Usage: rld-survivor-package REPOSITORY_ROOT NATIVE_BINARY FRESH_TAR_PATH".into(),
        );
    }
    let root = Path::new(&a[1]);
    let binary = read(Path::new(&a[2]))?;
    if !binary.starts_with(b"\x7fELF")
        && !binary.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        && !binary.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
    {
        return Err("unsupported native binary image".into());
    }
    let mut files = vec![
        ("rld-survivor-node".to_string(), binary, true),
        (
            "README.md".to_string(),
            read(&root.join("tools/survivor-node/README.md"))?,
            false,
        ),
        ("LICENSE".to_string(), read(&root.join("LICENSE"))?, false),
    ];
    for name in [
        "README.md",
        "CONSENSUS.md",
        "OPERATIONS.md",
        "CONFORMANCE.md",
        "SPECIFICATION.json",
        "vectors.json",
    ] {
        let path = format!("docs/protocol/survivor-v1/{name}");
        files.push((path.clone(), read(&root.join(path))?, false));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let checksums = files
        .iter()
        .map(|(name, bytes, _)| format!("{}  {name}\n", hex::encode(Sha256::digest(bytes))))
        .collect::<String>();
    let path = Path::new(&a[3]);
    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    for (name, bytes, executable) in files {
        append(&mut out, &name, &bytes, executable)?;
    }
    append(&mut out, "SHA256SUMS", checksums.as_bytes(), false)?;
    out.write_all(&[0; 1024])
        .and_then(|_| out.sync_all())
        .map_err(|e| e.to_string())?;
    drop(out);
    let mut hash = Sha256::new();
    let mut input = File::open(path).map_err(|e| e.to_string())?;
    let mut buffer = [0; 65536];
    loop {
        let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let digest = hex::encode(hash.finalize());
    let basename = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("archive basename")?;
    let checksum = path.with_extension("tar.sha256");
    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(checksum)
        .map_err(|e| e.to_string())?;
    writeln!(out, "{digest}  {basename}")
        .and_then(|_| out.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"archive":path,"sha256":digest,"profile":"RLD-SURVIVOR-1","network_kind":"NO_VALUE_ONLY","release_signature":null})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
