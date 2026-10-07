//! TEST ONLY deterministic official public-vector comparator. No generated keys,
//! networking, stored real keys or production key establishment.
use fips203::{
    ml_kem_768,
    traits::{KeyGen, SerDes},
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
    if check_only {
        return Ok(ml_kem_768::DecapsKey::try_from_bytes(exact(&args[2])?).is_ok());
    }
    if args.len() != 5 {
        return Err("expected check/dk2400 or d32/z32/ek1184/dk2400 files".into());
    }
    // Solely publicly known official standard d/z, never production entropy.
    let (ek, dk) = ml_kem_768::KG::keygen_from_seed(exact(&args[1])?, exact(&args[2])?);
    let expected_ek = exact::<1184>(&args[3])?;
    let expected_dk = exact::<2400>(&args[4])?;
    Ok(ek.into_bytes() == expected_ek && dk.into_bytes() == expected_dk)
}
fn main() {
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => println!(
            "test-only ML-KEM-768 expected bytes matched; API success is not authentication"
        ),
        Ok(false) => {
            eprintln!("candidate dk check or known answer refused");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate input unavailable: {error}");
            std::process::exit(2);
        }
    }
}
