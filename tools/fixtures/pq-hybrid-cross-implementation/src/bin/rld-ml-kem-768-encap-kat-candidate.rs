//! TEST ONLY deterministic official public-vector comparator. No generated keys,
//! networking, stored real keys or production key establishment.
use fips203::{
    ml_kem_768,
    traits::{Encaps, SerDes},
    SharedSecretKey,
};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

fn exact<const N: usize>(path: &str) -> Result<[u8; N], String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "known vector input unavailable")?;
    let metadata = file.metadata().map_err(|_| "vector stat unavailable")?;
    if metadata.uid() != unsafe { libc::getuid() }
        || !metadata.is_file()
        || metadata.len() != N as u64
        || metadata.mode() & 0o077 != 0
    {
        return Err("vector input requires exact private regular file".into());
    }
    let mut raw = Vec::new();
    file.take(N as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "vector read failed")?;
    raw.try_into().map_err(|_| "vector length changed".into())
}

fn verify(args: &[String]) -> Result<bool, String> {
    let check_only = args.len() == 3 && args[1] == "check";
    if !check_only && args.len() != 5 {
        return Err("expected check/ek1184 or ek1184/m32/c1088/k32 files".into());
    }
    let raw = exact(&args[if check_only { 2 } else { 1 }])?;
    let ek = match ml_kem_768::EncapsKey::try_from_bytes(raw) {
        Ok(key) => key,
        Err(_) => return Ok(false),
    };
    if check_only {
        return Ok(true);
    }
    let entropy = exact::<32>(&args[2])?;
    let expected_c = exact::<1088>(&args[3])?;
    let expected_k = SharedSecretKey::try_from_bytes(exact(&args[4])?)
        .map_err(|_| "known expected shared bytes invalid")?;
    // Supported deterministic API, solely for known standard test entropy.
    let (computed_k, computed_c) = ek.encaps_from_seed(&entropy);
    Ok(computed_c.into_bytes() == expected_c && computed_k == expected_k)
}
fn main() {
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => println!(
            "test-only ML-KEM-768 expected bytes matched; API success is not authentication"
        ),
        Ok(false) => {
            eprintln!("candidate key check or known answer refused");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate input unavailable: {error}");
            std::process::exit(2);
        }
    }
}
