//! Test helper: every seed accepted here is a deliberately public fixture.
//! It cannot read a private wallet and never applies its own ledger transitions.
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rld_core::{sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_regional_ledger_candidate::{
    storage::{read_json, Store},
    *,
};
use std::path::PathBuf;
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Bootstrap {
        #[arg(long)]
        bft: bool,
        #[arg(long, conflicts_with_all = ["bft", "segmented"])]
        bft_epochs: bool,
        #[arg(long, conflicts_with_all = ["bft", "bft_epochs", "segmented"])]
        bft_joint: bool,
        #[arg(long, conflicts_with_all = ["bft", "bft_epochs", "bft_joint", "segmented"])]
        bft_joint_roles: bool,
        #[arg(long, conflicts_with = "bft")]
        segmented: bool,
    },
    Intent {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        currency: String,
        #[arg(long)]
        request: PathBuf,
    },
}
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn sign(seed: u8, bytes: &[u8]) -> Result<String> {
    sign_bytes(&hex::encode([seed; 32]), bytes)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Pay {
    seed: u8,
    amount: Amount,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Remote {
    region: String,
    seed: u8,
    amount: Amount,
    fee: Amount,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    owners: Vec<u8>,
    inputs: Option<Vec<Hash>>,
    outputs: Vec<Pay>,
    remote: Option<Remote>,
    fee: Amount,
}
fn run() -> Result<()> {
    match Args::parse().action {
        Action::Bootstrap {
            bft,
            segmented,
            bft_epochs,
            bft_joint,
            bft_joint_roles,
        } => {
            let mut currency = Currency {
                format: "RLD-REGIONAL-FIXTURE-V1".into(),
                fixture_only: true,
                implementation: implementation()?,
                origin: "earth".into(),
                authority: public(1),
                cap: Amount(300),
                block_reward: Amount(100),
                maturity: 2,
                signature: String::new(),
            };
            currency.signature = sign(1, &currency.bytes()?)?;
            let admissions = [("earth", 2u8), ("proxima", 22u8), ("andromeda", 42u8)]
                .into_iter()
                .map(|(region, start)| {
                    let mut validators = (start..start + 4).map(public).collect::<Vec<_>>();
                    validators.sort();
                    let mut admission = Admission {
                        currency: currency.id()?,
                        region: region.into(),
                        rules: if segmented {
                            crate::segmented::RULES
                        } else if bft_joint_roles {
                            bft::ROLE_RULES
                        } else if bft_joint {
                            bft::JOINT_RULES
                        } else if bft_epochs {
                            bft::EPOCH_RULES
                        } else if bft {
                            bft::RULES
                        } else {
                            "RLD-REGIONAL-FIXTURE-V1"
                        }
                        .into(),
                        value_rules: None,
                        validators,
                        signature: String::new(),
                    };
                    admission.signature = sign(1, &admission.bytes()?)?;
                    Ok(admission)
                })
                .collect::<Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::to_string(&Bootstrap {
                    currency,
                    admissions
                })
                .map_err(|e| e.to_string())?
            );
        }
        Action::Intent {
            dir,
            currency,
            request,
        } => {
            let store = Store::open(
                &dir,
                &public(1),
                Hash::from_hex(&currency).map_err(|e| e.to_string())?,
            )?;
            let request: Request = read_json(&request)?;
            if request.owners.is_empty() || request.owners.len() > 16 || request.outputs.len() > 16
            {
                return Err("fixture request bounds".into());
            }
            let mut inputs = request.inputs.unwrap_or_else(|| {
                store
                    .chain
                    .ledger
                    .coins
                    .iter()
                    .filter(|(_, c)| {
                        request.owners.iter().any(|s| public(*s) == c.payment.owner)
                            && c.mature <= store.chain.height() + 1
                    })
                    .map(|(id, _)| *id)
                    .collect()
            });
            inputs.sort();
            let destination = request
                .remote
                .as_ref()
                .map(|r| store.trust.named(&r.region))
                .transpose()?;
            let intent = Intent {
                currency: store.trust.currency()?,
                region: store.chain.region,
                inputs,
                outputs: request
                    .outputs
                    .into_iter()
                    .map(|p| Payment {
                        owner: public(p.seed),
                        amount: p.amount,
                    })
                    .collect(),
                fee: request.fee,
                destination,
                remote: request.remote.as_ref().map(|r| Payment {
                    owner: public(r.seed),
                    amount: r.amount,
                }),
                destination_fee: request.remote.map(|r| r.fee).unwrap_or(Amount::ZERO),
                valid_through: if store.chain.is_segmented() {
                    store
                        .chain
                        .height()
                        .checked_add(32)
                        .ok_or("fixture expiry overflow")?
                } else {
                    100
                },
            };
            let mut approvals = request
                .owners
                .into_iter()
                .map(|seed| {
                    Ok(Approval {
                        key: public(seed),
                        signature: sign(seed, &intent.bytes()?)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            approvals.sort_by(|a, b| a.key.cmp(&b.key));
            println!(
                "{}",
                serde_json::json!({"export_or_transaction_id":intent.id()?,"command":Command::Spend(Box::new(SignedIntent{intent,approvals})),"fixture_only":true})
            );
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("public contact fixture helper rejected: {error}");
        std::process::exit(1);
    }
}
