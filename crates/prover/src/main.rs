use anyhow::{Context, Result, ensure};
use bincode::Options;
use clap::{Parser, Subcommand};
use risc0_zkvm::{ExecutorEnv, InnerReceipt, ProverOpts, Receipt, default_prover, sha::Digest};
use rld_protocol::{
    codec::{Id, decode, encode},
    model::ProofProfile,
    proof::{self, ControllerWitness, NativeInput},
};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Profile,
    Native {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Controller {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn load(path: &Path) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    ensure!(f.metadata()?.len() <= 1024 * 1024 * 1024, "witness limit");
    let mut b = Vec::new();
    f.take(1024 * 1024 * 1024 + 1).read_to_end(&mut b)?;
    ensure!(b.len() <= 1024 * 1024 * 1024, "witness limit");
    Ok(b)
}
fn assumptions(
    value: &serde_json::Value,
    out: &mut Vec<Receipt>,
    seen: &mut BTreeSet<Id>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "receipt" {
                    if let Some(encoded) = value.as_str() {
                        if !encoded.is_empty() {
                            let bytes = hex::decode(encoded)?;
                            ensure!(
                                bytes.len() <= rld_protocol::MAX_RECEIPT,
                                "assumption receipt limit"
                            );
                            let id = Id::digest(&bytes);
                            if seen.insert(id) {
                                let r: Receipt = bincode::DefaultOptions::new()
                                    .with_fixint_encoding()
                                    .with_limit(rld_protocol::MAX_RECEIPT as u64)
                                    .reject_trailing_bytes()
                                    .deserialize(&bytes)?;
                                ensure!(
                                    matches!(r.inner, InnerReceipt::Succinct(_)),
                                    "fake/composite/unsupported assumption"
                                );
                                out.push(r);
                            }
                        }
                    }
                }
                assumptions(value, out, seen)?;
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                assumptions(v, out, seen)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn profile() -> ProofProfile {
    let (root, params) = proof::default_parameters();
    ProofProfile {
        native_image: Id(Digest::from(rld_methods::NATIVE_ID).into()),
        controller_image: Id(Digest::from(rld_methods::CONTROLLER_ID).into()),
        control_root: root,
        verifier_parameters: params,
        backend: "risc0-zkvm-3.0.6-succinct".into(),
    }
}
fn prove(
    bytes: Vec<u8>,
    elf: &[u8],
    image: Id,
    journal: Vec<u8>,
    witness: serde_json::Value,
    output: &Path,
) -> Result<()> {
    ensure!(!output.exists(), "fresh proof output required");
    let mut receipts = vec![];
    assumptions(&witness, &mut receipts, &mut BTreeSet::new())?;
    let mut builder = ExecutorEnv::builder();
    builder.write(&bytes)?;
    for receipt in receipts {
        builder.add_assumption(receipt);
    }
    let env = builder.build()?;
    let result = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
    result.receipt.verify(Digest::from(image.0))?;
    ensure!(
        result.receipt.journal.bytes == journal,
        "proved journal mismatch"
    );
    let encoded = proof::encode_receipt(&result.receipt)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(output)?;
    file.write_all(&encode(&encoded))?;
    file.sync_all()?;
    fs::File::open(output.parent().context("proof parent")?)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"image":image,"receipt_bytes":encoded.0.len(),"unconditional_verified":true,"output":output})
    );
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    let expected = profile();
    match args.command {
        Command::Profile => println!("{}", serde_json::to_string_pretty(&expected)?),
        Command::Native { input, output } => {
            let bytes = load(&input)?;
            let witness: NativeInput = decode(&bytes, 1024 * 1024 * 1024)?;
            let (p, journal) = match &witness {
                NativeInput::Execution(w) => (
                    &w.currency.proof,
                    proof::native_journal(&proof::execute_native(w)?),
                ),
                NativeInput::IndexedExecution(w) => (
                    &w.currency.proof,
                    proof::native_journal(&proof::execute_indexed_native(w)?),
                ),
                NativeInput::IndexedPermanent(w) => (
                    &w.native.currency.proof,
                    proof::native_journal(&proof::execute_indexed_permanent(w)?),
                ),
                NativeInput::IndexedUtxo(w) => (
                    &w.native.native.currency.proof,
                    proof::native_journal(&proof::execute_indexed_utxo(w)?),
                ),
                NativeInput::IndexedMint(w) => (
                    &w.native.native.native.currency.proof,
                    proof::native_journal(&proof::execute_indexed_mint(w)?),
                ),
                NativeInput::MintIndex(w) => (
                    &w.currency.proof,
                    rld_protocol::mints::index::journal(&rld_protocol::mints::index::execute(w)?),
                ),
                NativeInput::Admission(w) => (&w.currency.proof, proof::execute_admission(w)?),
            };
            ensure!(
                p == &expected,
                "currency program/verifier binding does not match this build"
            );
            let json = serde_json::to_value(&witness)?;
            prove(
                bytes,
                rld_methods::NATIVE_ELF,
                expected.native_image,
                journal,
                json,
                &output,
            )?;
        }
        Command::Controller { input, output } => {
            let bytes = load(&input)?;
            let witness: ControllerWitness = decode(&bytes, 1024 * 1024 * 1024)?;
            ensure!(
                witness.currency.proof == expected,
                "currency proof profile does not match this build"
            );
            let journal = proof::terminal_journal(&proof::execute_controller(&witness)?);
            let json = serde_json::to_value(&witness)?;
            prove(
                bytes,
                rld_methods::CONTROLLER_ELF,
                expected.controller_image,
                journal,
                json,
                &output,
            )?;
        }
    }
    Ok(())
}
