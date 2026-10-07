//! NIST external pure ML-DSA-87 signature-verification vectors only.
//! Arbitrary vector messages never qualify candidate or ledger authorization.
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Verifier},
};
use std::{fs::File, io::Read, path::Path};

fn bounded(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "vector input unavailable")?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("invalid vector input bound".into());
    }
    let file = File::open(path).map_err(|_| "vector input unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "vector input stat failed")?
        .is_file()
    {
        return Err("non-file vector input".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "vector input read failed")?;
    if bytes.len() > maximum {
        return Err("vector input exceeds bound".into());
    }
    Ok(bytes)
}

fn verify(args: &[String]) -> Result<bool, String> {
    if args.len() != 5 {
        return Err("expected public raw key, signature, message and context files".into());
    }
    let key: [u8; 2592] = bounded(&args[1], 2592)?
        .try_into()
        .map_err(|_| "vector public key length")?;
    let signature: [u8; 4627] = bounded(&args[2], 4627)?
        .try_into()
        .map_err(|_| "vector signature length")?;
    let message = bounded(&args[3], 65536)?;
    let context = bounded(&args[4], 255)?;
    let key = ml_dsa_87::PublicKey::try_from_bytes(key).map_err(|_| "vector public key invalid")?;
    Ok(key.verify(&message, &signature, &context))
}

fn main() {
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => {
            println!("ML-DSA-87 pure signature vector valid; no authority granted");
        }
        Ok(false) => {
            println!("ML-DSA-87 pure signature vector invalid");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("ML-DSA vector unavailable: {error}");
            std::process::exit(2);
        }
    }
}
