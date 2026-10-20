mod builder;
use anyhow::{Context, Result, bail, ensure};
use clap::{Args as ClapArgs, Parser, Subcommand};
use rand::{RngCore, rngs::OsRng};
use rld_node::{
    custody::{Binding, Vault},
    runtime::{Initial, Node},
    service,
    store::{MAX_RECORD, private_create, read_bounded},
};
use rld_protocol::{
    codec::{Amount, Blob, Id, decode, encode, hash},
    crypto,
    model::*,
    proof::{self, NativeInput},
    work,
};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "rld",
    about = "RLD controller protocol node, wallet, public-work miner and operator tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Profile,
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Currency {
        #[command(subcommand)]
        command: CurrencyCommand,
    },
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    Mine(MineArgs),
    Draft {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        nonce: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    ClaimWork {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    FamilyId {
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        source: String,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        issuer: PathBuf,
    },
    Handoff {
        #[command(subcommand)]
        action: HandoffAction,
    },
    Relay {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        spool: PathBuf,
        #[arg(long, default_value_t = 268435456)]
        capacity_bytes: u64,
        #[command(subcommand)]
        action: RelayAction,
    },
    Encode {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Decode {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        input: PathBuf,
    },
}
#[derive(Subcommand)]
enum HandoffAction {
    Draft {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long, required = true)]
        inventory: Vec<PathBuf>,
        #[arg(long)]
        fee_policy: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Attest {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        new: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Assemble {
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        admission: PathBuf,
        #[arg(long, required = true)]
        old_attestation: Vec<PathBuf>,
        #[arg(long, required = true)]
        new_attestation: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffDraft {
    currency: Currency,
    previous: Configuration,
    prestate: Id,
    next: Configuration,
}
#[derive(Subcommand)]
enum RelayAction {
    Export {
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long)]
        output: PathBuf,
    },
    Import {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        pinned_sender: String,
        #[arg(long)]
        receipt: PathBuf,
    },
}
#[derive(Clone, ClapArgs)]
struct KeyFile {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    key_head: PathBuf,
    #[arg(long)]
    password_stdin: bool,
}
#[derive(Clone, ClapArgs)]
struct StoreArgs {
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    latest_head: PathBuf,
}
#[derive(Clone, ClapArgs)]
struct Api {
    #[arg(long)]
    node: String,
    #[arg(long)]
    tls_certificate: Option<PathBuf>,
    #[arg(long)]
    tls_pin: Option<String>,
}
#[derive(Subcommand)]
enum KeyCommand {
    Create(KeyFile),
    Public(KeyFile),
    Recover(KeyFile),
    Validator {
        #[command(flatten)]
        output: KeyFile,
        #[arg(long)]
        identity_key: PathBuf,
        #[arg(long)]
        identity_head: PathBuf,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        pool_epoch: u64,
        #[arg(long)]
        public_inventory: PathBuf,
    },
}
#[derive(Subcommand)]
enum CurrencyCommand {
    Draft {
        #[arg(long)]
        bootstrap_identity: PathBuf,
        #[arg(long, required = true)]
        bootstrap_validator: Vec<String>,
        #[arg(long)]
        proof_profile: PathBuf,
        #[arg(long, default_value = "research")]
        network: String,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[arg(long)]
        input: PathBuf,
    },
}
#[derive(Subcommand)]
enum DomainCommand {
    Identity {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        nonce: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Draft {
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long, required = true)]
        inventory: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        fee_policy: Option<PathBuf>,
    },
    Admission {
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        configuration: PathBuf,
        #[arg(long, required = true)]
        inventory: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Attest {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        configuration: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Assemble {
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        configuration: PathBuf,
        #[arg(long)]
        admission: PathBuf,
        #[arg(long, required = true)]
        attestation: Vec<PathBuf>,
        #[arg(long)]
        identity_signature: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum NodeCommand {
    Init {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
    },
    Serve {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        signer: Vec<PathBuf>,
        #[arg(long)]
        signer_head: Vec<PathBuf>,
        #[arg(long)]
        transport_key: PathBuf,
        #[arg(long)]
        transport_head: PathBuf,
        #[arg(long)]
        password_stdin: bool,
    },
    Recover(StoreArgs),
    Inspect(StoreArgs),
    Archive(StoreArgs),
    RecoveryDraft {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        output: PathBuf,
    },
    Closure {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        coupon: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    StateWitness {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        collection: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        output: PathBuf,
    },
    StateProof {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        collection: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        output: PathBuf,
    },
    Funding {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        service: String,
        #[arg(long)]
        output: PathBuf,
    },
    Coupon {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        family: PathBuf,
        #[arg(long)]
        index: u32,
        #[arg(long)]
        output: PathBuf,
    },
    Witness {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    MintIndexWitness {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    MintIndexCertificate {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Certificate {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        at: u64,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Status(Api),
    Submit {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        operation: PathBuf,
    },
}
#[derive(Subcommand)]
enum WalletCommand {
    Sign {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        operation: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Balance {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        public_key: String,
    },
    RemoteBalance {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        public_key: String,
    },
}
#[derive(Subcommand)]
enum ControllerCommand {
    Witness {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        output: PathBuf,
    },
    Release {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
    },
    CancelDraft {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        output: PathBuf,
    },
    CancelFetch {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        currency: PathBuf,
        #[arg(long)]
        original_operation: PathBuf,
        #[arg(long)]
        controller_output: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    CancelSign {
        #[command(flatten)]
        key: KeyFile,
        #[arg(long)]
        controller: PathBuf,
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    CancelSubmit {
        #[command(flatten)]
        api: Api,
        #[arg(long)]
        input: PathBuf,
    },
}
#[derive(ClapArgs)]
struct MineArgs {
    #[command(flatten)]
    api: Api,
    #[command(flatten)]
    key: KeyFile,
    #[arg(long)]
    currency: PathBuf,
    #[arg(long, default_value_t = 1)]
    threads: usize,
    #[arg(long, default_value_t = 2)]
    refresh_seconds: u64,
}
fn random() -> Id {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    Id(bytes)
}
fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read_bounded(path, MAX_RECORD)?)?)
}
fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    private_create(path, &bytes)?;
    rld_node::store::sync_dir(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}
fn password(stdin: bool, label: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = if stdin {
        let mut value = Vec::new();
        io::stdin().take(4097).read_to_end(&mut value)?;
        while value.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            value.pop();
        }
        value
    } else {
        rpassword::prompt_password(format!("Password for {}: ", label.display()))?.into_bytes()
    };
    ensure!(!bytes.is_empty() && bytes.len() <= 4096, "password length");
    Ok(Zeroizing::new(bytes))
}
fn open_key(args: &KeyFile) -> Result<Vault> {
    let secret = password(args.password_stdin, &args.key)?;
    Vault::open(&args.key, &args.key_head, &secret)
}
fn open_node(args: &StoreArgs) -> Result<Node> {
    Node::open(&args.store, &args.latest_head, false)
}
fn read_currency(path: &Path) -> Result<Currency> {
    let c: Currency = json(path)?;
    c.validate()?;
    ensure!(
        c.proof == rld_node::executable_profile()?,
        "currency program binding differs from this executable; retain old currency/state and use its matching release"
    );
    Ok(c)
}
fn client(api: &Api) -> Result<reqwest::Client> {
    let url = reqwest::Url::parse(&api.node)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "plain node endpoint required"
    );
    if let (Some(cert), Some(pin)) = (&api.tls_certificate, &api.tls_pin) {
        return service::peer_client(&rld_node::transport::Peer {
            identity: Id::ZERO,
            domain: Id::ZERO,
            endpoint: api.node.clone(),
            certificate_pem: cert.to_string_lossy().into_owned(),
            certificate_sha256: Id::parse(pin)?,
        });
    }
    ensure!(
        api.tls_certificate.is_none() && api.tls_pin.is_none(),
        "certificate and pin must be supplied together"
    );
    if url.scheme() == "http" {
        ensure!(
            url.host_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()),
            "unencrypted API is restricted to literal loopback"
        );
    } else {
        ensure!(url.scheme() == "https", "HTTPS required");
    }
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .timeout(Duration::from_secs(30))
        .build()?)
}
async fn response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|n| n <= rld_protocol::MAX_CAPSULE),
            "response size"
        );
        bytes.extend_from_slice(&chunk);
    }
    ensure!(
        status.is_success(),
        "node rejected request: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(bytes)
}
async fn get(api: &Api, path: &str) -> Result<Vec<u8>> {
    response(
        client(api)?
            .get(format!("{}{}", api.node.trim_end_matches('/'), path))
            .send()
            .await?,
    )
    .await
}
async fn post<T: minicbor::Encode<()>>(api: &Api, path: &str, value: &T) -> Result<()> {
    let bytes = encode(value);
    ensure!(bytes.len() <= rld_protocol::MAX_CAPSULE, "submission size");
    let result = response(
        client(api)?
            .post(format!("{}{}", api.node.trim_end_matches('/'), path))
            .header("content-type", "application/cbor")
            .body(bytes)
            .send()
            .await?,
    )
    .await?;
    println!("{}", String::from_utf8_lossy(&result));
    Ok(())
}
fn add_signature(op: &mut Operation, policy: Owner, key: &Vault) -> Result<()> {
    policy.validate()?;
    let bytes = op.signing_bytes();
    for existing in &op.authorizations {
        for sig in &existing.signatures {
            ensure!(
                existing.owner.keys.contains(&sig.key),
                "unknown prior signer"
            );
            crypto::verify_signature(sig, &bytes)?;
        }
    }
    let signature = key.sign_owner(&policy, &bytes)?;
    if let Some(a) = op.authorizations.iter_mut().find(|a| a.owner == policy) {
        if !a.signatures.iter().any(|s| s.key == signature.key) {
            a.signatures.push(signature);
            a.signatures.sort_by_key(|s| s.key);
        }
    } else {
        op.authorizations.push(Authorization {
            owner: policy,
            signatures: vec![signature],
        });
    }
    op.authorizations.sort_by_key(|a| a.owner.id(op.currency));
    Ok(())
}
fn controller_witness(node: &Node, id: Id) -> Result<proof::ControllerWitness> {
    let creation = node.core.creation(id)?;
    let c = &creation.controller;
    let birth = node
        .core
        .state
        .births
        .get(id)?
        .context("controller birth")?;
    let record = node
        .core
        .history
        .at(birth.sequence)?
        .context("preparation record")?;
    let material = record
        .batch
        .operations
        .iter()
        .find_map(|op| match &op.command {
            CommandProtocol::PreparePayment {
                ticket, material, ..
            }
            | CommandProtocol::PrepareClaim {
                ticket, material, ..
            } if ticket.id == id => Some(material.clone()),
            _ => None,
        })
        .context("preparation material")?;
    let m: Material = decode(&material.0, rld_protocol::MAX_CAPSULE)?;
    let terminal = Terminal {
        currency: node.core.state.currency,
        controller: id,
        initial: hash("RLD-CONTROLLER", node.core.state.currency, c),
        source_checkpoint: creation.source.header.id(),
        decision: 1,
        ticket_or_return: c.ticket.digest(node.core.state.currency),
        material_root: c.material_root,
    };
    Ok(proof::ControllerWitness {
        currency: node.core.initial.currency.clone(),
        creation,
        terminal,
        material,
        covers: m.covers,
        cancellation_authorization: None,
    })
}
use rld_protocol::model::Command as CommandProtocol;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Cli::parse();
    match args.command {
        Command::Profile => println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"source_digest":rld_node::executable_source_digest(),"proof_profile":rld_node::executable_profile()?})
            )?
        ),
        Command::Handoff { action } => match action {
            HandoffAction::Draft {
                store,
                inventory,
                fee_policy,
                output,
            } => {
                let node = open_node(&store)?;
                let state = &node.core.state;
                let mut inventories = inventory
                    .iter()
                    .map(|p| json::<PublicInventory>(p))
                    .collect::<Result<Vec<_>>>()?;
                inventories.sort_by_key(|i| i.validator);
                let mut next = state.configuration.clone();
                next.epoch = next.epoch.checked_add(1).context("epoch exhaustion")?;
                next.pool_epoch = next
                    .pool_epoch
                    .checked_add(1)
                    .context("pool epoch exhaustion")?;
                next.first_sequence = state
                    .sequence
                    .checked_add(2)
                    .context("sequence exhaustion")?;
                next.validators = inventories
                    .iter()
                    .map(|i| Validator {
                        identity: i.validator,
                        native_root: Id::ZERO,
                        controller_root: Id::ZERO,
                    })
                    .collect();
                if let Some(p) = fee_policy {
                    next.fee_policy = json(&p)?;
                }
                for (i, inv) in inventories.iter().enumerate() {
                    next.validators[i].native_root =
                        crypto::validate_inventory(&next, inv.validator, false, &inv.native)?;
                    next.validators[i].controller_root =
                        crypto::validate_inventory(&next, inv.validator, true, &inv.controller)?;
                }
                next.validate()?;
                save(
                    &output,
                    &HandoffDraft {
                        currency: node.core.initial.currency.clone(),
                        previous: state.configuration.clone(),
                        prestate: state.root()?,
                        next,
                    },
                )?;
            }
            HandoffAction::Attest {
                key,
                draft,
                new,
                output,
            } => {
                let draft: HandoffDraft = json(&draft)?;
                draft.currency.validate()?;
                let config = if new { &draft.next } else { &draft.previous };
                let mut vault = open_key(&key)?;
                ensure!(
                    config
                        .validators
                        .iter()
                        .any(|v| v.identity == vault.binding().identity),
                    "not a handoff identity"
                );
                let tag = if new {
                    "RLD-HANDOFF-ACK"
                } else {
                    "RLD-HANDOFF-AUTHORIZATION"
                };
                let bytes = rld_protocol::codec::tagged(
                    tag,
                    draft.currency.id(),
                    &(draft.previous.id(), &draft.next, draft.prestate),
                );
                let scope = hash(
                    "RLD-HANDOFF-APPROVAL-SCOPE",
                    draft.currency.id(),
                    &(
                        tag,
                        draft.next.domain,
                        draft.next.epoch,
                        draft.next.first_sequence,
                    ),
                );
                save(&output, &vault.sign_approval(scope, &bytes)?)?;
            }
            HandoffAction::Assemble {
                draft,
                admission,
                old_attestation,
                new_attestation,
                output,
            } => {
                let draft: HandoffDraft = json(&draft)?;
                let mut old = old_attestation
                    .iter()
                    .map(|p| json::<Signature>(p))
                    .collect::<Result<Vec<_>>>()?;
                let mut new = new_attestation
                    .iter()
                    .map(|p| json::<Signature>(p))
                    .collect::<Result<Vec<_>>>()?;
                old.sort_by_key(|s| s.key);
                new.sort_by_key(|s| s.key);
                crypto::identity_attestations(
                    &draft.previous,
                    &old,
                    &rld_protocol::codec::tagged(
                        "RLD-HANDOFF-AUTHORIZATION",
                        draft.currency.id(),
                        &(draft.previous.id(), &draft.next, draft.prestate),
                    ),
                )?;
                crypto::identity_attestations(
                    &draft.next,
                    &new,
                    &rld_protocol::codec::tagged(
                        "RLD-HANDOFF-ACK",
                        draft.currency.id(),
                        &(draft.previous.id(), &draft.next, draft.prestate),
                    ),
                )?;
                let admission = InventoryAdmission {
                    configuration: draft.next.id(),
                    receipt: decode(
                        &read_bounded(&admission, rld_protocol::MAX_RECEIPT + 128)?,
                        rld_protocol::MAX_RECEIPT + 128,
                    )?,
                };
                proof::Verifier {
                    currency: &draft.currency,
                }
                .admission(&draft.next, &admission)?;
                let op = Operation {
                    currency: draft.currency.id(),
                    home: draft.next.domain,
                    nonce: random(),
                    command: CommandProtocol::Handoff(Handoff {
                        next: draft.next,
                        new_acknowledgments: new,
                        admission,
                        old_authorizations: old,
                    }),
                    covers: vec![],
                    authorizations: vec![],
                };
                save(&output, &op)?;
            }
        },
        Command::Relay {
            key,
            currency,
            spool,
            capacity_bytes,
            action,
        } => {
            let currency = read_currency(&currency)?;
            let mut vault = open_key(&key)?;
            let spool =
                rld_node::transport::Spool::open(&spool, currency.id(), capacity_bytes, 4096)?;
            match action {
                RelayAction::Export { cursor, output } => {
                    let bundle =
                        rld_node::offline::export(&spool, currency.id(), &mut vault, cursor)?;
                    private_create(&output, &encode(&bundle))?;
                }
                RelayAction::Import {
                    input,
                    pinned_sender,
                    receipt,
                } => {
                    let bundle: rld_node::offline::Bundle = decode(
                        &read_bounded(&input, rld_protocol::MAX_CAPSULE)?,
                        rld_protocol::MAX_CAPSULE,
                    )?;
                    let ack = rld_node::offline::import(
                        &spool,
                        currency.id(),
                        &mut vault,
                        Id::parse(&pinned_sender)?,
                        &bundle,
                    )?;
                    save(&receipt, &ack)?;
                    println!(
                        "bytes durably retained; ledger acceptance and spendability require native verification"
                    );
                }
            }
        }
        Command::Draft {
            store,
            request,
            nonce,
            output,
        } => {
            let node = open_node(&store)?;
            let nonce = nonce
                .map(|s| Id::parse(&s))
                .transpose()?
                .unwrap_or_else(random);
            let op = builder::build(&node.core.state, nonce, json(&request)?)?;
            save(&output, &op)?;
            println!("unsigned draft {}; inputs remain unreserved", op.id());
        }
        Command::FamilyId {
            currency,
            source,
            destination,
            nonce,
            issuer,
        } => {
            let c = read_currency(&currency)?;
            println!(
                "{}",
                builder::family_id(
                    c.id(),
                    Id::parse(&source)?,
                    Id::parse(&destination)?,
                    Id::parse(&nonce)?,
                    &json::<Owner>(&issuer)?
                )
            );
        }
        Command::ClaimWork {
            key,
            currency,
            template,
            output,
        } => {
            let currency = read_currency(&currency)?;
            let vault = open_key(&key)?;
            let mut w: PlacementWork = json(&template)?;
            ensure!(
                w.claimant.threshold == 1 && w.claimant.keys == vec![vault.binding().identity],
                "single-owner work search; threshold owners may independently combine exact raw claim authorizations"
            );
            let weight = w.range.hi.checked_sub(w.range.lo).context("range bounds")?;
            ensure!((1..=256).contains(&weight), "claim range size");
            loop {
                let bytes = work::claim_bytes(currency.id(), &w);
                if work::meets(work::evaluate(currency.id(), &bytes)?, weight) {
                    w.authorization = Authorization {
                        owner: w.claimant.clone(),
                        signatures: vec![vault.sign_owner(&w.claimant, &bytes)?],
                    };
                    work::verify_claim(currency.id(), &w)?;
                    save(&output, &w)?;
                    println!("placement work found; no slots or money have moved");
                    break;
                }
                w.nonce = random();
            }
        }
        Command::Key { command } => match command {
            KeyCommand::Create(args) => {
                let secret = password(args.password_stdin, &args.key)?;
                let key = Vault::create_wallet(&args.key, &args.key_head, &secret)?;
                println!(
                    "{}",
                    serde_json::json!({"public_key":key,"private_key_written_to":args.key,"latest_head":args.key_head})
                );
            }
            KeyCommand::Recover(args) => {
                let secret = password(args.password_stdin, &args.key)?;
                Vault::recover_publication(&args.key, &args.key_head, &secret)?;
                println!("retained publication reconciled; no new signature created");
            }
            KeyCommand::Public(args) => {
                let vault = open_key(&args)?;
                println!("{}", vault.binding().identity);
            }
            KeyCommand::Validator {
                output,
                identity_key,
                identity_head,
                currency,
                domain,
                epoch,
                pool_epoch,
                public_inventory,
            } => {
                let currency = read_currency(&currency)?;
                let secret = password(output.password_stdin, &output.key)?;
                let identity = Vault::open(&identity_key, &identity_head, &secret)?;
                let binding = Binding {
                    currency: currency.id(),
                    domain: Id::parse(&domain)?,
                    identity: identity.binding().identity,
                    epoch,
                    pool_epoch,
                    purpose: "validator".into(),
                };
                let inventory = Vault::create_validator(
                    &output.key,
                    &output.key_head,
                    &secret,
                    binding,
                    &identity,
                )?;
                save(&public_inventory, &inventory)?;
                println!("public inventory: {}", public_inventory.display());
            }
        },
        Command::Currency { command } => match command {
            CurrencyCommand::Draft {
                bootstrap_identity,
                bootstrap_validator,
                proof_profile,
                network,
                output,
            } => {
                let identity: DomainIdentity = json(&bootstrap_identity)?;
                let mut validators = bootstrap_validator
                    .iter()
                    .map(|s| Id::parse(s))
                    .collect::<Result<Vec<_>>>()?;
                validators.sort();
                let currency = Currency {
                    bootstrap: identity.id(),
                    roots: rld_protocol::ROOTS,
                    slots: rld_protocol::SLOTS,
                    reward: Amount(rld_protocol::REWARD),
                    atoms: Amount(rld_protocol::ATOMS),
                    cap: Amount(rld_protocol::CAP),
                    proof: json(&proof_profile)?,
                    limits: Limits::default(),
                    succession: Id::digest(b"RLD-HANDOFF-1"),
                    work_profile: work::profile_id(),
                    encoding: rld_protocol::ENCODING.into(),
                    bootstrap_validators: validators,
                    network,
                };
                currency.validate()?;
                ensure!(
                    currency.proof == rld_node::executable_profile()?,
                    "draft must use this source-bound executable's real compiled proof profile"
                );
                save(&output, &currency)?;
                println!("{}", currency.id());
            }
            CurrencyCommand::Inspect { input } => {
                let currency = read_currency(&input)?;
                println!(
                    "{}",
                    serde_json::json!({"currency":currency.id(),"cap_RLD":"21000000","initial_allocation_RLD":"0","network":currency.network,"proof":currency.proof})
                );
            }
        },
        Command::Domain { command } => match command {
            DomainCommand::Identity { key, nonce, output } => {
                let vault = open_key(&key)?;
                let identity = DomainIdentity {
                    key: vault.binding().identity,
                    nonce: nonce
                        .map(|s| Id::parse(&s))
                        .transpose()?
                        .unwrap_or_else(random),
                };
                save(&output, &identity)?;
                println!("{}", identity.id());
            }
            DomainCommand::Draft {
                currency,
                identity,
                inventory,
                output,
                fee_policy,
            } => {
                let currency = read_currency(&currency)?;
                let identity: DomainIdentity = json(&identity)?;
                let mut inventories = inventory
                    .iter()
                    .map(|p| json::<PublicInventory>(p))
                    .collect::<Result<Vec<_>>>()?;
                inventories.sort_by_key(|i| i.validator);
                let validators = inventories
                    .iter()
                    .map(|i| Validator {
                        identity: i.validator,
                        native_root: Id::ZERO,
                        controller_root: Id::ZERO,
                    })
                    .collect();
                let mut config = Configuration {
                    currency: currency.id(),
                    domain: identity.id(),
                    epoch: 0,
                    first_sequence: 1,
                    pool_epoch: 0,
                    validators,
                    initial_anchor: Id::ZERO,
                    succession: Id::digest(b"RLD-HANDOFF-1"),
                    signature_profile: Id::digest(b"RLD-ED25519-HEIGHT-POOL-PBFT-SUMMARY-2"),
                    custody_profile: Id::digest(b"RLD-SOFTWARE-CUSTODY-UNQUALIFIED-1"),
                    limits: Limits::default(),
                    fee_policy: if let Some(path) = fee_policy {
                        json(&path)?
                    } else {
                        let owner = Owner {
                            threshold: 1,
                            keys: vec![identity.key],
                        };
                        FeePolicy {
                            service_owner: owner.clone(),
                            archive_owner: owner.clone(),
                            archive_custodians: owner,
                            minimum_service: Amount(1),
                            minimum_archive: Amount(1),
                            minimum_work_author: Amount(1),
                        }
                    },
                };
                for i in 0..config.validators.len() {
                    let id = config.validators[i].identity;
                    config.validators[i].native_root =
                        crypto::validate_inventory(&config, id, false, &inventories[i].native)?;
                    config.validators[i].controller_root =
                        crypto::validate_inventory(&config, id, true, &inventories[i].controller)?;
                }
                let draft = DomainGenesis {
                    identity,
                    configuration: config.clone(),
                    attestations: vec![],
                    identity_signature: Signature {
                        key: Id::ZERO,
                        bytes: Blob(vec![]),
                    },
                    admission: InventoryAdmission {
                        configuration: Id::ZERO,
                        receipt: Blob(vec![]),
                    },
                };
                config.initial_anchor = rld_protocol::state::initial_anchor(currency.id(), &draft);
                config.validate()?;
                save(&output, &config)?;
                println!("{}", config.id());
            }
            DomainCommand::Admission {
                currency,
                configuration,
                inventory,
                output,
            } => {
                let currency = read_currency(&currency)?;
                let configuration: Configuration = json(&configuration)?;
                let mut inventories = inventory
                    .iter()
                    .map(|p| json::<PublicInventory>(p))
                    .collect::<Result<Vec<_>>>()?;
                inventories.sort_by_key(|i| i.validator);
                let input = NativeInput::Admission(AdmissionWitness {
                    currency,
                    configuration,
                    inventories,
                });
                private_create(&output, &encode(&input))?;
            }
            DomainCommand::Attest {
                key,
                identity,
                configuration,
                output,
            } => {
                let mut vault = open_key(&key)?;
                let identity: DomainIdentity = json(&identity)?;
                let config: Configuration = json(&configuration)?;
                let signature = vault.sign_approval(
                    rld_protocol::codec::hash(
                        "RLD-DOMAIN-ADMISSION-SCOPE",
                        config.currency,
                        &identity.id(),
                    ),
                    &rld_protocol::codec::tagged(
                        "RLD-DOMAIN-ADMISSION",
                        config.currency,
                        &(identity, &config),
                    ),
                )?;
                save(&output, &signature)?;
            }
            DomainCommand::Assemble {
                currency,
                identity,
                configuration,
                admission,
                attestation,
                identity_signature,
                output,
            } => {
                let currency = read_currency(&currency)?;
                let configuration: Configuration = json(&configuration)?;
                let receipt: Blob = decode(
                    &read_bounded(&admission, rld_protocol::MAX_RECEIPT + 128)?,
                    rld_protocol::MAX_RECEIPT + 128,
                )?;
                let mut signatures = attestation
                    .iter()
                    .map(|p| json::<Signature>(p))
                    .collect::<Result<Vec<_>>>()?;
                signatures.sort_by_key(|s| s.key);
                let g = DomainGenesis {
                    identity: json(&identity)?,
                    admission: InventoryAdmission {
                        configuration: configuration.id(),
                        receipt,
                    },
                    configuration,
                    attestations: signatures,
                    identity_signature: json(&identity_signature)?,
                };
                rld_protocol::state::State::genesis(&currency, &g)?;
                save(&output, &g)?;
            }
        },
        Command::Node { command } => match command {
            NodeCommand::Init {
                store,
                currency,
                genesis,
            } => {
                let initial = Initial {
                    currency: read_currency(&currency)?,
                    genesis: json(&genesis)?,
                };
                let n = Node::initialize(&store.store, &store.latest_head, initial)?;
                println!(
                    "{}",
                    serde_json::json!({"currency":n.core.state.currency,"domain":n.core.state.domain,"issued_RLD":"0","network":n.core.initial.currency.network})
                );
            }
            NodeCommand::Serve {
                store,
                config,
                signer,
                signer_head,
                transport_key,
                transport_head,
                password_stdin,
            } => {
                ensure!(
                    signer.len() == signer_head.len(),
                    "one separately retained head per signer"
                );
                let mut node = open_node(&store)?;
                let config: service::Config = json(&config)?;
                let secret = password(password_stdin, &transport_key)?;
                let transport = Vault::open(&transport_key, &transport_head, &secret)?;
                for (path, head) in signer.iter().zip(&signer_head) {
                    let pass = if password_stdin {
                        Zeroizing::new(secret.to_vec())
                    } else {
                        password(false, path)?
                    };
                    node.add_signer(Vault::open(path, head, &pass)?)?;
                }
                service::serve(node, transport, config).await?;
            }
            NodeCommand::Recover(store) => {
                let node = Node::open(&store.store, &store.latest_head, true)?;
                println!("{}", node.journal_tip());
            }
            NodeCommand::Archive(store) => {
                let mut node = open_node(&store)?;
                let mut count = 0u64;
                while node.archive_history()? {
                    count = count.checked_add(1).context("archive count exhaustion")?;
                }
                println!(
                    "{}",
                    serde_json::json!({"sealed_segments":count,"journal_head":node.journal_tip(),"monetary_state_unchanged":true})
                );
            }
            NodeCommand::Inspect(store) => {
                let node = open_node(&store)?;
                println!(
                    "{}",
                    serde_json::json!({"currency":node.core.state.currency,"domain":node.core.state.domain,"height":node.core.state.sequence,"head":node.core.head,"queued":node.core.pending.len(),"proofs":node.core.proofs.len(),"failed_requests":node.core.failed})
                );
            }
            NodeCommand::RecoveryDraft {
                store,
                controller,
                output,
            } => {
                let node = open_node(&store)?;
                let id = Id::parse(&controller)?;
                let rejected = node
                    .core
                    .rejections
                    .iter()
                    .find(|v| v.release.creation.controller.id == id)
                    .context("certified destination rejection has not arrived")?
                    .clone();
                let op = Operation {
                    currency: node.core.state.currency,
                    home: node.core.state.domain,
                    nonce: random(),
                    command: CommandProtocol::RedeemRejected(rejected),
                    covers: vec![],
                    authorizations: vec![],
                };
                save(&output, &op)?;
                println!(
                    "unsigned recovery; original recovery owner must authorize this exact operation"
                );
            }
            NodeCommand::Closure {
                store,
                at,
                coupon,
                output,
            } => {
                let node = open_node(&store)?;
                let state = node.core.state_at(at)?;
                let coupon: CouponEvidence = json(&coupon)?;
                let id = coupon.coupon.id(state.currency);
                let delegation = state
                    .coupon_uses
                    .get(id)?
                    .filter(|v| v.closed)
                    .context("source closure is not committed")?
                    .clone();
                let source = node
                    .core
                    .proofs
                    .get(at)?
                    .context("exact closure execution receipt not ready")?
                    .as_ref()
                    .clone();
                save(
                    &output,
                    &CapabilityClosure {
                        coupon,
                        source,
                        delegation,
                        inclusion: state.witness("coupon_uses", id)?,
                    },
                )?;
            }
            NodeCommand::StateWitness {
                store,
                at,
                collection,
                key,
                output,
            } => {
                let node = open_node(&store)?;
                save(
                    &output,
                    &node
                        .core
                        .proof_context()
                        .witness_at(at, &collection, Id::parse(&key)?)?,
                )?;
            }
            NodeCommand::StateProof {
                api,
                currency,
                checkpoint,
                at,
                collection,
                key,
                output,
            } => {
                let currency = read_currency(&currency)?;
                ensure!(
                    rld_protocol::state::COLLECTIONS.contains(&collection.as_str()),
                    "state collection"
                );
                let key = Id::parse(&key)?;
                let checkpoint = Id::parse(&checkpoint)?;
                let bytes = get(
                    &api,
                    &format!("/v1/state-proof?at={at}&collection={collection}&key={key}"),
                )
                .await?;
                let proof: rld_node::state_index::CertifiedQuery =
                    decode(&bytes, rld_protocol::MAX_CAPSULE)?;
                proof.verify(&currency, checkpoint, &collection, key)?;
                ensure!(
                    proof.query.collection == collection && proof.source.header.sequence == at,
                    "query collection/position differs from request"
                );
                save(&output, &proof)?;
            }
            NodeCommand::Funding {
                store,
                at,
                service,
                output,
            } => {
                let node = open_node(&store)?;
                let state = node.core.state_at(at)?;
                let id = Id::parse(&service)?;
                let service = state.services.get(id)?.context("service")?.clone();
                let source = node
                    .core
                    .proofs
                    .get(at)?
                    .context("exact execution receipt not ready")?
                    .as_ref()
                    .clone();
                save(
                    &output,
                    &Funding {
                        source,
                        service,
                        inclusion: state.witness("services", id)?,
                    },
                )?;
            }
            NodeCommand::Coupon {
                store,
                at,
                family,
                index,
                output,
            } => {
                let node = open_node(&store)?;
                let state = node.core.state_at(at)?;
                let f: FamilyFunding = json(&family)?;
                ensure!(
                    state.families.contains(&f.family, state.currency)?,
                    "family not present at exact checkpoint"
                );
                let coupon = f
                    .coupons
                    .iter()
                    .find(|c| c.index == index)
                    .context("coupon index")?
                    .clone();
                let mut leaves: Vec<_> = f
                    .coupons
                    .iter()
                    .map(|c| rld_protocol::merkle::Entry {
                        key: hash("RLD-COUPON-INDEX", state.currency, &c.index),
                        value: c.digest(state.currency),
                    })
                    .collect();
                leaves.sort_by_key(|e| e.key);
                let key = hash("RLD-COUPON-INDEX", state.currency, &index);
                let position = leaves
                    .binary_search_by_key(&key, |e| e.key)
                    .map_err(|_| anyhow::anyhow!("coupon leaf"))?;
                let certified = node
                    .core
                    .proofs
                    .get(at)?
                    .context("exact family receipt not ready")?
                    .as_ref()
                    .clone();
                let evidence = CouponEvidence {
                    coupon,
                    family: f.family.clone(),
                    leaf: rld_protocol::merkle::prove(
                        state.currency,
                        &format!("{}/coupons", f.family.id),
                        &leaves,
                        position,
                    )?,
                    certified,
                    reservation: state.witness("families", f.family.id)?,
                };
                proof::Verifier {
                    currency: &node.core.initial.currency,
                }
                .coupon(&evidence)?;
                save(&output, &evidence)?;
            }
            NodeCommand::Witness { store, at, output } => {
                let node = open_node(&store)?;
                private_create(
                    &output,
                    &rld_protocol::codec::encode_bounded(
                        &node.core.native_input(at)?,
                        rld_node::store::MAX_RECORD,
                    )?,
                )?;
            }
            NodeCommand::MintIndexWitness { store, at, output } => {
                let node = open_node(&store)?;
                private_create(
                    &output,
                    &rld_protocol::codec::encode_bounded(
                        &node.core.proof_context().mint_index_input(at)?,
                        rld_node::store::MAX_RECORD,
                    )?,
                )?;
            }
            NodeCommand::MintIndexCertificate {
                store,
                at,
                receipt,
                output,
            } => {
                let mut node = open_node(&store)?;
                let certificate = rld_protocol::mints::index::Certificate {
                    claim: node.core.proof_context().mint_claim_at(at)?,
                    receipt: decode(
                        &read_bounded(&receipt, rld_protocol::MAX_RECEIPT + 128)?,
                        rld_protocol::MAX_RECEIPT + 128,
                    )?,
                };
                node.mint_index_certificate(at, certificate.clone())?;
                save(&output, &certificate)?;
            }
            NodeCommand::Certificate {
                store,
                at,
                receipt,
                output,
            } => {
                let mut node = open_node(&store)?;
                let h = node.core.history.at(at)?.context("height not retained")?;
                let p = Certified {
                    header: h.header.clone(),
                    qc: h.qc.clone(),
                    configuration: h.configuration.clone(),
                    receipt: decode(
                        &read_bounded(&receipt, rld_protocol::MAX_RECEIPT + 128)?,
                        rld_protocol::MAX_RECEIPT + 128,
                    )?,
                };
                node.certificate(p.clone())?;
                save(&output, &p)?;
            }
            NodeCommand::Status(api) => {
                println!("{}", String::from_utf8(get(&api, "/v1/status").await?)?)
            }
            NodeCommand::Submit {
                api,
                currency,
                operation,
            } => {
                let currency = read_currency(&currency)?;
                let op: Operation = json(&operation)?;
                ensure!(op.currency == currency.id(), "foreign operation currency");
                post(&api, "/v1/submit", &op).await?;
            }
        },
        Command::Wallet { command } => match command {
            WalletCommand::Sign {
                key,
                operation,
                policy,
                output,
            } => {
                let vault = open_key(&key)?;
                let policy = if let Some(path) = policy {
                    json::<Owner>(&path)?
                } else {
                    Owner {
                        threshold: 1,
                        keys: vec![vault.binding().identity],
                    }
                };
                let mut op: Operation = json(&operation)?;
                add_signature(&mut op, policy, &vault)?;
                save(&output, &op)?;
                println!("{}", op.id());
            }
            WalletCommand::Balance { store, public_key } => {
                let node = open_node(&store)?;
                print_balance(&node.core.state, Id::parse(&public_key)?)?;
            }
            WalletCommand::RemoteBalance {
                api,
                currency,
                public_key,
            } => {
                let currency = read_currency(&currency)?;
                let state: rld_protocol::state::State =
                    decode(&get(&api, "/v1/state").await?, rld_protocol::MAX_CAPSULE)?;
                let p: Certified = decode(
                    &get(&api, "/v1/certified").await?,
                    rld_protocol::MAX_CAPSULE,
                )?;
                proof::Verifier {
                    currency: &currency,
                }
                .native(&p)?;
                ensure!(
                    state.currency == currency.id()
                        && state.domain == p.header.domain
                        && state.sequence == p.header.sequence
                        && state.root()? == p.header.new_root,
                    "state is not the certified current checkpoint"
                );
                state.invariants()?;
                print_balance(&state, Id::parse(&public_key)?)?;
            }
        },
        Command::Controller { command } => match command {
            ControllerCommand::Witness {
                store,
                controller,
                output,
            } => {
                let node = open_node(&store)?;
                private_create(
                    &output,
                    &encode(&controller_witness(&node, Id::parse(&controller)?)?),
                )?;
            }
            ControllerCommand::Release {
                api,
                witness,
                receipt,
            } => {
                let w: proof::ControllerWitness =
                    decode(&read_bounded(&witness, MAX_RECORD)?, MAX_RECORD)?;
                let r = Release {
                    creation: w.creation,
                    terminal: w.terminal,
                    receipt: decode(
                        &read_bounded(&receipt, rld_protocol::MAX_RECEIPT + 128)?,
                        rld_protocol::MAX_RECEIPT + 128,
                    )?,
                    qc: Quorum { votes: vec![] },
                    covers: w.covers,
                    material: w.material,
                };
                post(
                    &api,
                    "/v1/candidate",
                    &rld_protocol::consensus::Payload::Export(r),
                )
                .await?;
            }
            ControllerCommand::CancelDraft {
                store,
                controller,
                output,
            } => {
                let node = open_node(&store)?;
                let (_, cancel) = node.core.cancel_draft(Id::parse(&controller)?)?;
                save(&output, &cancel)?;
            }
            ControllerCommand::CancelFetch {
                api,
                currency,
                original_operation,
                controller_output,
                output,
            } => {
                let currency = read_currency(&currency)?;
                let op: Operation = json(&original_operation)?;
                ensure!(op.currency == currency.id(), "original currency");
                let ticket = match &op.command {
                    CommandProtocol::PreparePayment { ticket, .. }
                    | CommandProtocol::PrepareClaim { ticket, .. } => ticket,
                    _ => bail!("original preparation operation required"),
                };
                let (controller, cancel): (Controller, Cancellation) = decode(
                    &get(&api, &format!("/v1/cancel/{}", ticket.id)).await?,
                    rld_protocol::MAX_CAPSULE,
                )?;
                ensure!(
                    controller.ticket == *ticket
                        && controller.configuration.currency == currency.id()
                        && controller.source == op.home
                        && cancel.source_header.domain == op.home
                        && cancel.source_header.configuration == controller.configuration.id(),
                    "cancel draft differs from original owner intent"
                );
                proof::validate_controller(&controller)?;
                crypto::verify_quorum(
                    &controller.configuration,
                    op.home,
                    None,
                    &cancel.source_qc,
                    3,
                    cancel.source_header.id(),
                )?;
                ensure!(
                    cancel.source_qc.votes[0].sequence == cancel.source_header.sequence,
                    "birth certificate position"
                );
                let verifier = proof::Verifier {
                    currency: &currency,
                };
                verifier.witness(
                    &cancel.source_header,
                    "controllers",
                    controller.id,
                    hash("RLD-CONTROLLER", currency.id(), &controller),
                    &cancel.delegation,
                )?;
                let use_record = Delegation {
                    coupon: ticket.coupon,
                    controller: Some(ticket.id),
                    closed: false,
                };
                verifier.witness(
                    &cancel.source_header,
                    "coupon_uses",
                    ticket.coupon,
                    hash("RLD-DELEGATION", currency.id(), &use_record),
                    &cancel.coupon_use,
                )?;
                proof::validate_terminal(
                    &controller,
                    cancel.source_header.id(),
                    &cancel.terminal,
                    2,
                )?;
                save(&controller_output, &controller)?;
                save(&output, &cancel)?;
            }
            ControllerCommand::CancelSign {
                key,
                controller,
                draft,
                output,
            } => {
                let vault = open_key(&key)?;
                let c: Controller = json(&controller)?;
                let mut cancellation: Cancellation = json(&draft)?;
                ensure!(c.id == cancellation.controller, "wrong controller draft");
                let message = proof::cancellation_bytes(&c);
                let signature = vault.sign_owner(&c.ticket.cancel_policy, &message)?;
                for old in &cancellation.authorization.signatures {
                    crypto::verify_signature(old, &message)?;
                }
                if !cancellation
                    .authorization
                    .signatures
                    .iter()
                    .any(|s| s.key == signature.key)
                {
                    cancellation.authorization.signatures.push(signature);
                    cancellation.authorization.signatures.sort_by_key(|s| s.key);
                }
                save(&output, &cancellation)?;
            }
            ControllerCommand::CancelSubmit { api, input } => {
                let c: Cancellation = json(&input)?;
                post(
                    &api,
                    "/v1/candidate",
                    &rld_protocol::consensus::Payload::Cancel(c),
                )
                .await?;
            }
        },
        Command::Mine(args) => mine(args).await?,
        Command::Encode {
            kind,
            input,
            output,
        } => codec_command(&kind, &input, Some(&output))?,
        Command::Decode { kind, input } => codec_command(&kind, &input, None)?,
    }
    Ok(())
}

fn print_balance(state: &rld_protocol::state::State, key: Id) -> Result<()> {
    let mut owned = Amount(0);
    let mut shared = Amount(0);
    let mut quarantined = Amount(0);
    let mut outputs = Vec::new();
    for out in state.outputs.records() {
        let out = out?;
        if !out.owner.keys.contains(&key) {
            continue;
        }
        let n = rld_protocol::state::sum(&out.components)?;
        let mut blocked = false;
        for component in &out.components {
            let cover = state
                .covers
                .get(component.cover)?
                .context("wallet cover missing")?;
            for family in &cover.families {
                if state.incidents.known(family.family, family.anchor)? {
                    blocked = true;
                    break;
                }
            }
            if blocked {
                break;
            }
        }
        if blocked {
            quarantined = quarantined.add(n)?;
        } else if out.owner.threshold == 1 {
            owned = owned.add(n)?;
        } else {
            shared = shared.add(n)?;
        }
        outputs.push(out);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"currency":state.currency,"height":state.sequence,"spendable_atomic":owned,"threshold_shared_atomic":shared,"quarantined_atomic":quarantined,"outputs":outputs,"prepared_escrow_excluded":true})
        )?
    );
    Ok(())
}
fn codec_command(kind: &str, input: &Path, output: Option<&Path>) -> Result<()> {
    macro_rules! convert {
        ($t:ty) => {{
            if let Some(path) = output {
                let v: $t = json(input)?;
                private_create(path, &encode(&v))?;
            } else {
                let v: $t = decode(&read_bounded(input, MAX_RECORD)?, MAX_RECORD)?;
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
            Ok(())
        }};
    }
    match kind {
        "operation" => convert!(Operation),
        "currency" => convert!(Currency),
        "genesis" => convert!(DomainGenesis),
        "configuration" => convert!(Configuration),
        "release" => convert!(Release),
        "cancellation" => convert!(Cancellation),
        "certificate" => convert!(Certified),
        "native-input" => convert!(NativeInput),
        "controller-witness" => convert!(proof::ControllerWitness),
        "state" => convert!(rld_protocol::state::State),
        "coupon" => convert!(CouponEvidence),
        _ => bail!("unsupported typed codec kind"),
    }
}
async fn mine(args: MineArgs) -> Result<()> {
    ensure!(
        (1..=64).contains(&args.threads) && (1..=60).contains(&args.refresh_seconds),
        "miner resource bounds"
    );
    let currency = read_currency(&args.currency)?;
    let vault = Arc::new(Mutex::new(open_key(&args.key)?));
    let public = vault
        .lock()
        .map_err(|_| anyhow::anyhow!("wallet unavailable"))?
        .binding()
        .identity;
    let payout = Owner {
        threshold: 1,
        keys: vec![public],
    };
    let client = client(&args.api)?;
    loop {
        let bytes = response(
            client
                .get(format!("{}/v1/work", args.api.node.trim_end_matches('/')))
                .send()
                .await?,
        )
        .await?;
        let (advertised, config, _covers, tasks): (
            Currency,
            Configuration,
            Vec<Cover>,
            Vec<(Grant, Segment)>,
        ) = decode(&bytes, rld_protocol::MAX_CAPSULE)?;
        ensure!(
            advertised == currency && config.currency == currency.id(),
            "miner currency mismatch"
        );
        ensure!(!tasks.is_empty(), "no active issuance frontiers available");
        let mut workers = Vec::new();
        for worker in 0..args.threads {
            let (grant, segment) = tasks[worker % tasks.len()].clone();
            let payout = payout.clone();
            let c = currency.id();
            let duration = Duration::from_secs(args.refresh_seconds);
            workers.push(tokio::task::spawn_blocking(
                move || -> Result<Option<Work>> {
                    let until = Instant::now() + duration;
                    let mut work = Work {
                        grant: grant.id,
                        slot: segment.cursor,
                        home: grant.home,
                        anchor: segment.mint_anchor,
                        payout,
                        cover: grant.cover,
                        nonce: random(),
                        signature: Signature {
                            key: Id::ZERO,
                            bytes: Blob(vec![]),
                        },
                    };
                    while Instant::now() < until {
                        let z = work::mint_bytes(c, &work);
                        if work::meets(work::evaluate(c, &z)?, 1) {
                            return Ok(Some(work));
                        }
                        work.nonce = random();
                    }
                    Ok(None)
                },
            ));
        }
        for worker in workers {
            if let Some(mut solution) = worker.await?? {
                let z = work::mint_bytes(currency.id(), &solution);
                solution.signature = vault
                    .lock()
                    .map_err(|_| anyhow::anyhow!("wallet unavailable"))?
                    .sign_owner(&payout, &z)?;
                let op = Operation {
                    currency: currency.id(),
                    home: solution.home,
                    nonce: random(),
                    command: CommandProtocol::Mint(solution),
                    covers: vec![],
                    authorizations: vec![],
                };
                match post(&args.api, "/v1/submit", &op).await {
                    Ok(()) => println!(
                        "Mint solution queued: {}; reward requires certified inclusion",
                        op.id()
                    ),
                    Err(error) => eprintln!("solution not accepted: {error}"),
                }
            }
        }
    }
}
