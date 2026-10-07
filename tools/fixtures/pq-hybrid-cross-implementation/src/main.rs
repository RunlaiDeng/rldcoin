//! Public-material-only interoperability probe. It grants no protocol authority.
use fips204::{
    ml_dsa_87,
    traits::{SerDes, Verifier},
};
use std::{fs::File, io::Read, path::Path};

fn bounded(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let path = Path::new(path);
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "public input unavailable")?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("public input is not a bounded regular file".into());
    }
    let file = File::open(path).map_err(|_| "public input open failed")?;
    if !file
        .metadata()
        .map_err(|_| "public input stat failed")?
        .is_file()
    {
        return Err("public input is not a regular file".into());
    }
    let mut data = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "public input read failed")?;
    if data.len() > maximum {
        return Err("public input exceeds bound".into());
    }
    Ok(data)
}

fn verify(args: &[String]) -> Result<bool, String> {
    if !(6..=7).contains(&args.len()) {
        return Err(
            "expected Ed/PQ public DER, Ed/PQ signature, message, optional expected context".into(),
        );
    }
    let ed = bounded(&args[1], 44)?;
    let pq = bounded(&args[2], 2614)?;
    let ed_signature = bounded(&args[3], 64)?;
    let pq_signature = bounded(&args[4], 4627)?;
    let message = bounded(&args[5], 2048)?;
    let context = args
        .get(6)
        .map_or("RLDCOIN-PQ-AUTH-CANDIDATE-V1", String::as_str)
        .as_bytes();
    if context.len() > 255 {
        return Err("expected context exceeds bound".into());
    }
    let ed_prefix = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let pq_prefix = [
        0x30, 0x82, 0x0a, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x03, 0x13, 0x03, 0x82, 0x0a, 0x21, 0x00,
    ];
    if ed.len() != 44
        || pq.len() != 2614
        || !ed.starts_with(&ed_prefix)
        || !pq.starts_with(&pq_prefix)
        || ed_signature.len() != 64
        || pq_signature.len() != 4627
        || !message.starts_with(b"RLDCOIN-HYBRID-AUTH-CANDIDATE-V1\0")
    {
        return Ok(false);
    }
    let ed_key: [u8; 32] = ed[ed_prefix.len()..]
        .try_into()
        .map_err(|_| "classical key length")?;
    let ed_key =
        ed25519_dalek::VerifyingKey::from_bytes(&ed_key).map_err(|_| "classical key invalid")?;
    let ed_signature = ed25519_dalek::Signature::from_slice(&ed_signature)
        .map_err(|_| "classical signature length")?;
    let pq_key: [u8; 2592] = pq[pq_prefix.len()..]
        .try_into()
        .map_err(|_| "PQ key length")?;
    let pq_key = ml_dsa_87::PublicKey::try_from_bytes(pq_key).map_err(|_| "PQ key invalid")?;
    let pq_signature: [u8; 4627] = pq_signature.try_into().map_err(|_| "PQ signature length")?;
    let classical = ed_key.verify_strict(&message, &ed_signature).is_ok();
    let post_quantum = pq_key.verify(&message, &pq_signature, context);
    Ok(classical && post_quantum)
}

fn main() {
    match verify(&std::env::args().collect::<Vec<_>>()) {
        Ok(true) => {
            println!("candidate dual signatures verified; no authority granted");
        }
        Ok(false) => {
            println!("candidate dual signatures rejected");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("candidate verification unavailable: {error}");
            std::process::exit(2);
        }
    }
}
