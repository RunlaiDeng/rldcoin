//! Known public standard-vector comparator only; no key generation, TLS,
//! secret output or production key establishment. Decap success is not auth.
use fips203::{
    ml_kem_768,
    traits::{Decaps, SerDes},
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
    if !metadata.is_file() || metadata.len() != N as u64 || metadata.mode() & 0o077 != 0 {
        return Err("vector input requires exact private regular file".into());
    }
    let mut raw = Vec::new();
    file.take(N as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "vector read failed")?;
    raw.try_into().map_err(|_| "vector length changed".into())
}

fn verify(args: &[String]) -> Result<bool, String> {
    if args.len() != 4 {
        return Err("expected known vector dk2400, c1088, k32 files".into());
    }
    let dk = ml_kem_768::DecapsKey::try_from_bytes(exact(&args[1])?)
        .map_err(|_| "known standard decapsulation key invalid")?;
    let c = ml_kem_768::CipherText::try_from_bytes(exact(&args[2])?)
        .map_err(|_| "known standard ciphertext invalid")?;
    let expected = SharedSecretKey::try_from_bytes(exact(&args[3])?)
        .map_err(|_| "known expected bytes invalid")?;
    let computed = dk
        .try_decaps(&c)
        .map_err(|_| "known vector operation unavailable")?;
    Ok(computed == expected)
}

fn main() {
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => println!(
            "candidate ML-KEM-768 expected bytes matched; API success is not authentication"
        ),
        Ok(false) => {
            eprintln!("candidate ML-KEM known answer differs");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate ML-KEM vector unavailable: {error}");
            std::process::exit(2);
        }
    }
}
