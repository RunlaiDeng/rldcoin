use clap::{Parser, Subcommand};
use rld_core::AdmissionHash32 as Hash;
use rld_regional_ledger_candidate::{
    storage::{read_json, Store},
    *,
};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Fixture-only generic regional ledger; no mainnet or remote HTTP")]
struct Args {
    #[arg(long)]
    dir: PathBuf,
    #[arg(long)]
    authority: String,
    #[arg(long)]
    currency: String,
    /// Normal startup enables relay; a contact file is optional when isolated.
    #[arg(long)]
    mesh_config: Option<PathBuf>,
    /// Explicit validator configuration, separate from discovered mesh identity.
    #[arg(long)]
    bft_config: Option<PathBuf>,
    /// Normal startup includes a bounded TCP listener, loopback ephemeral by default.
    #[arg(long)]
    mesh_listen: Option<String>,
    /// Explicit ground-only plaintext adapter; never used as a TLS fallback.
    #[arg(long)]
    mesh_insecure_tcp: bool,
    /// Explicitly opt into local import block production, separate from relaying.
    #[arg(long)]
    miner: Option<String>,
    #[arg(long, default_value = "python3")]
    transport_python: PathBuf,
    #[arg(long, default_value_t = 1.0)]
    interval: f64,
    #[command(subcommand)]
    action: Option<Action>,
}
#[derive(Subcommand)]
enum Action {
    BftPendingImports,
    BftRetainedMessages {
        #[arg(long)]
        signer_dir: PathBuf,
    },
    BftSubmit {
        #[arg(long)]
        file: PathBuf,
    },
    BftNetworkCheck {
        #[arg(long)]
        file: PathBuf,
    },
    /// Bounded full cold authentication only; no ledger installation or signing.
    BftNetworkCheckBatch {
        #[arg(long)]
        file: PathBuf,
    },
    /// Full bounded live authentication only; no ledger installation or signing.
    BftNetworkInspectBatch {
        #[arg(long)]
        file: PathBuf,
    },
    BftNetworkPack {
        #[arg(long)]
        file: PathBuf,
    },
    BftSync {
        #[arg(long)]
        file: PathBuf,
    },
    BftContext,
    /// Exact historical proofs actually installed by fully replayed local events.
    BftInstalledEpochs,
    JointReadyInit {
        #[arg(long)]
        ready_dir: PathBuf,
        #[arg(long)]
        key: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        observe_only: bool,
    },
    JointReadyRecoverInit {
        #[arg(long)]
        ready_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    JointVoterRecoverInit {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    JointVoterInit {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        key: String,
        #[arg(long)]
        ready_dir: PathBuf,
        #[arg(long)]
        expected_ready_head: String,
        #[arg(long, requires = "expected_old_head")]
        old_signer_dir: Option<PathBuf>,
        #[arg(long, requires = "old_signer_dir")]
        expected_old_head: Option<String>,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        observe_only: bool,
    },
    JointReadyStatus {
        #[arg(long)]
        ready_dir: PathBuf,
    },
    JointReadySign {
        #[arg(long)]
        ready_dir: PathBuf,
        #[arg(long)]
        expected_head: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        recover_only: bool,
    },
    BftInitObservation,
    BftEpochProposal {
        #[arg(long)]
        checkpoint: Option<String>,
    },
    BftEpochCombine {
        #[arg(long)]
        file: PathBuf,
    },
    BftEpochActivate {
        #[arg(long)]
        file: PathBuf,
    },
    BftEpochActivateObserved {
        #[arg(long)]
        file: PathBuf,
        /// Select an ordered proof from this exact fully authenticated envelope.
        #[arg(long)]
        carried_index: Option<usize>,
    },
    BftInit {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        key: String,
    },
    BftStatus {
        #[arg(long)]
        signer_dir: PathBuf,
    },
    BftCandidate {
        #[arg(long)]
        commands: Option<PathBuf>,
        #[arg(long)]
        miner: String,
    },
    BftSign {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        expected_head: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        recover_only: bool,
    },
    BftQuorum {
        #[arg(long)]
        file: PathBuf,
    },
    BftTimeoutCertificate {
        #[arg(long)]
        file: PathBuf,
    },
    BftCertify {
        #[arg(long)]
        file: PathBuf,
    },
    /// Create an encrypted random owner key; no balance or issuance is created.
    WalletKeyCreate {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    WalletKeyCheck {
        #[arg(long)]
        encrypted_key: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Back up the encrypted key plus complete validated signed/reserved journal.
    WalletBackup {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
        #[arg(long)]
        encrypted_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Restore to a fresh directory; requires independently retained latest head.
    WalletRestore {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    Init {
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        region: String,
    },
    Status,
    /// Replay a private bounded archive from pinned genesis; never adopt a store.
    HistoryStreamCheck {
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        region: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    /// Check compact read-only history; reconstruct and replay every native block.
    HistoryStreamCompactCheck {
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        region: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    /// Prove a historical record from an already native-replayed checkpoint.
    StateProof {
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        collection: String,
        #[arg(long)]
        key: String,
    },
    /// Check exact caller-selected checkpoint/query; grants no spending rights.
    StateProofCheck {
        #[arg(long)]
        checkpoint: String,
        #[arg(long)]
        collection: String,
        #[arg(long)]
        key: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Exact storage observation, to retain separately; not an independent anchor.
    HistoryHead,
    /// Check the separately retained exact head, then replay native authority/value.
    HistoryCheck {
        #[arg(long)]
        expected_head: String,
    },
    /// Seal a private ledger-only image against a separately retained latest head.
    HistoryArchive {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    /// Restore a private ledger image into this fresh --dir; never restore keys.
    HistoryRestore {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    WalletContext,
    /// Public ledger ownership/eligibility only; no peer wallet journal.
    WalletCoins {
        #[arg(long, num_args = 1..=16)]
        owner: Vec<String>,
    },
    WalletApp {
        #[arg(long)]
        backup_dir: Option<PathBuf>,
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        head_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        expected_wallet_head: Option<String>,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]
        encrypted_key: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        miner: Option<String>,
    },
    WalletInit {
        #[arg(long)]
        owner: String,
        #[arg(long)]
        wallet_dir: PathBuf,
    },
    WalletView {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
    },
    WalletRecover {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
        #[arg(long)]
        intent: String,
    },
    WalletPrepare {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
    },
    WalletSign {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]
        encrypted_key: Option<PathBuf>,
        #[arg(long, requires = "encrypted_key")]
        passphrase_stdin: bool,
        /// Return an exact retained command only; never read a key or first-sign.
        #[arg(long)]
        recover_only: bool,
        #[arg(long)]
        review: String,
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        expected_wallet_head: String,
    },
    WalletReceipt {
        #[arg(long)]
        file: PathBuf,
    },
    ChannelReceiptAccept {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    ChannelWitnessInit {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        witness: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerInit {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        expected_witness_head: String,
        #[arg(long)]
        witness_key_file: PathBuf,
        #[arg(long)]
        owner_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerPrepare {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        expected_witness_head: String,
        #[arg(long)]
        owner_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected_owner_head: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerSign {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        expected_witness_head: String,
        #[arg(long)]
        witness_key_file: PathBuf,
        #[arg(long)]
        owner_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        review: String,
        #[arg(long)]
        expected_owner_head: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerRecover {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        expected_witness_head: String,
        #[arg(long)]
        owner_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        review: String,
        #[arg(long)]
        expected_owner_head: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerFinishWitness {
        #[arg(long)]
        witness_dir: PathBuf,
        #[arg(long)]
        expected_witness_head: String,
        #[arg(long)]
        witness_key_file: PathBuf,
        #[arg(long)]
        owner_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        review: String,
        #[arg(long)]
        expected_owner_head: String,
        #[arg(long)]
        expected_head: String,
    },
    ChannelOwnerCombine {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected_head: String,
    },
    WalletCombine {
        #[arg(long)]
        file: PathBuf,
    },
    Mine {
        #[arg(long)]
        miner: String,
        #[arg(long)]
        commands: Option<PathBuf>,
    },
    Evidence {
        #[arg(long)]
        file: PathBuf,
    },
    Finalize {
        #[arg(long)]
        file: PathBuf,
    },
    Proof,
    Incident {
        #[arg(long)]
        file: PathBuf,
    },
    Incidents,
    RecoverIncident {
        #[arg(long)]
        file: PathBuf,
    },
    Statement,
    ContactExport {
        #[arg(long)]
        export: String,
    },
    ContactApply {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        miner: Option<String>,
    },
    ContactStatus,
    ContactOutgoing,
    ContactResume {
        #[arg(long)]
        message: String,
        #[arg(long)]
        miner: String,
    },
    ContactNode {
        #[arg(long)]
        mesh_config: Option<PathBuf>,
        #[arg(long)]
        bft_config: Option<PathBuf>,
        #[arg(long)]
        mesh_listen: Option<String>,
        #[arg(long)]
        mesh_insecure_tcp: bool,
        #[arg(long)]
        miner: Option<String>,
        #[arg(long, default_value = "python3")]
        transport_python: PathBuf,
        #[arg(long, default_value_t = 1.0)]
        interval: f64,
    },
    ProposeEpoch {
        #[arg(long)]
        validators: PathBuf,
    },
    InstallEpoch {
        #[arg(long)]
        file: PathBuf,
    },
    SignerInit {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        key: String,
    },
    SignerRecoverHandoff {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected_lock: String,
    },
    SignerStatus {
        #[arg(long)]
        signer_dir: PathBuf,
    },
    SignCheckpoint {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        expected_lock: String,
    },
    SignHandoff {
        #[arg(long)]
        signer_dir: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        expected_lock: String,
        #[arg(long)]
        file: PathBuf,
    },
}
fn require_local_interval(interval: f64) -> Result<()> {
    if interval.is_finite() && (0.1..=3600.0).contains(&interval) {
        Ok(())
    } else {
        Err("contact poll interval outside bound".into())
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    let pin = Hash::from_hex(&args.currency).map_err(|e| e.to_string())?;
    rld_regional_ledger_candidate::storage::ensure_not_restoring(&args.dir)?;
    let action = args.action.unwrap_or(Action::ContactNode {
        mesh_config: args.mesh_config,
        bft_config: args.bft_config,
        mesh_listen: args.mesh_listen,
        mesh_insecure_tcp: args.mesh_insecure_tcp,
        miner: args.miner,
        transport_python: args.transport_python.clone(),
        interval: args.interval,
    });
    if let Action::HistoryStreamCheck {
        ref bootstrap,
        ref region,
        ref file,
        ref expected_head,
    }
    | Action::HistoryStreamCompactCheck {
        ref bootstrap,
        ref region,
        ref file,
        ref expected_head,
    } = action
    {
        let genesis = read_json::<Bootstrap>(bootstrap)?;
        let expected = Hash::from_hex(expected_head).map_err(|e| e.to_string())?;
        let compact = matches!(action, Action::HistoryStreamCompactCheck { .. });
        let head = if compact {
            stream_archive::check_archive(file, &genesis, &args.authority, pin, region, expected)?
        } else {
            stream_replay::check_archive(file, &genesis, &args.authority, pin, region, expected)?
        };
        println!(
            "{}",
            serde_json::json!({"head":head,"genesis_and_every_native_block_replayed":true,
            "compact_archive":compact,
            "ledger_adopted":false,"signing_or_wallet_custody_restored":false,
            "incident_quarantine_reconciled":false,"ordinary_node_storage_upgraded":false,
            "independent_latest_anchor_qualified":false,"long_history_qualified":false,
            "fixture_only":true,"live_rld":false})
        );
        return Ok(());
    }
    if let Action::ContactNode {
        ref mesh_config,
        ref bft_config,
        ref mesh_listen,
        mesh_insecure_tcp,
        ref miner,
        ref transport_python,
        interval,
    } = action
    {
        require_local_interval(interval)?;
        if let Some(listen) = mesh_listen {
            let address: std::net::SocketAddr = listen
                .parse()
                .map_err(|_| "TCP listener must be literal IPv4:port")?;
            if !address.is_ipv4() {
                return Err("this contact adapter supports IPv4 listeners only".into());
            }
        }
        if let Some(miner) = miner {
            rld_core::validate_ed25519_public_key(miner)?;
        }
        let driver =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/regional_contact_node.py");
        let mut command = std::process::Command::new(transport_python);
        command.arg(driver).args([
            "--binary",
            std::env::current_exe()
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("binary path is not UTF-8")?,
            "--ledger",
            args.dir.to_str().ok_or("ledger path is not UTF-8")?,
            "--authority",
            &args.authority,
            "--currency",
            &args.currency,
            "--interval",
            &interval.to_string(),
        ]);
        if let Some(config) = mesh_config {
            command.arg("--mesh-config").arg(config);
        }
        if let Some(config) = bft_config {
            command.arg("--bft-config").arg(config);
        }
        if let Some(listen) = mesh_listen {
            command.arg("--listen").arg(listen);
        }
        if mesh_insecure_tcp {
            command.arg("--insecure-tcp");
        }
        if let Some(miner) = miner {
            command.arg("--miner").arg(miner);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            return Err(command.exec().to_string());
        }
        #[cfg(not(unix))]
        {
            let status = command.status().map_err(|e| e.to_string())?;
            return if status.success() {
                Ok(())
            } else {
                Err("native contact node companion stopped; inspect its explicit diagnostic".into())
            };
        }
    }
    if let Action::WalletApp {
        ref backup_dir,
        ref wallet_dir,
        ref head_dir,
        ref owner,
        ref expected_wallet_head,
        ref key_file,
        ref encrypted_key,
        port,
        ref miner,
    } = action
    {
        rld_core::validate_ed25519_public_key(owner)?;
        let driver =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/regional_wallet_app.py");
        let mut command = std::process::Command::new(&args.transport_python);
        command
            .arg(driver)
            .arg("--binary")
            .arg(std::env::current_exe().map_err(|e| e.to_string())?)
            .arg("--ledger")
            .arg(&args.dir)
            .arg("--authority")
            .arg(&args.authority)
            .arg("--currency")
            .arg(&args.currency)
            .arg("--wallet-dir")
            .arg(wallet_dir)
            .arg("--head-dir")
            .arg(head_dir)
            .arg("--owner")
            .arg(owner)
            .arg("--port")
            .arg(port.to_string());
        if let Some(head) = expected_wallet_head {
            command.arg("--expected-wallet-head").arg(head);
        }
        if let Some(key) = key_file {
            command.arg("--key-file").arg(key);
        }
        if let Some(key) = encrypted_key {
            command.arg("--encrypted-key").arg(key);
        }
        if let Some(dir) = backup_dir {
            command.arg("--backup-dir").arg(dir);
        }
        if let Some(miner) = miner {
            command.arg("--miner").arg(miner);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            return Err(command.exec().to_string());
        }
        #[cfg(not(unix))]
        {
            return if command.status().map_err(|e| e.to_string())?.success() {
                Ok(())
            } else {
                Err("local wallet app stopped".into())
            };
        }
    }
    if let Action::Init { bootstrap, region } = action {
        let bootstrap: Bootstrap = read_json(&bootstrap)?;
        let trust = Trust::verify(&bootstrap, &args.authority, pin)?;
        let store = Store::create(
            &args.dir,
            bootstrap,
            trust.named(&region)?,
            &args.authority,
            pin,
        )?;
        println!(
            "{}",
            serde_json::json!({"region":store.chain.region,"height":0,"fixture_only":true,"live_rld":false})
        );
        return Ok(());
    }
    if let Action::HistoryArchive {
        ref archive,
        ref expected_head,
    }
    | Action::HistoryRestore {
        ref archive,
        ref expected_head,
    } = action
    {
        let head = Hash::from_hex(expected_head).map_err(|e| e.to_string())?;
        let result = if matches!(action, Action::HistoryRestore { .. }) {
            rld_regional_ledger_candidate::history_archive::restore(
                archive,
                &args.dir,
                &args.authority,
                pin,
                head,
            )?
        } else {
            rld_regional_ledger_candidate::history_archive::seal(
                &args.dir,
                archive,
                &args.authority,
                pin,
                head,
            )?
        };
        println!(
            "{}",
            serde_json::json!({"format":result.format,"currency":result.currency,"region":result.region,"history_head":result.native_head,"archive_commitment":result.commitment()?,"retained_files":result.files.len(),"retained_bytes":result.retained_bytes,"complete_native_replay_verified":true,"keys_restored":false,"signer_or_caller_heads_restored":false,"wallet_pending_reviews_restored":false,"independent_latest_anchor_qualified":false,"fixture_only":true,"live_rld":false})
        );
        return Ok(());
    }
    if let Action::RecoverIncident { ref file } = action {
        rld_regional_ledger_candidate::storage::recover_incident(
            &args.dir,
            &args.authority,
            pin,
            read_json::<rld_regional_ledger_candidate::conflict::Incident>(file)?,
        )?;
    }
    let mut store = match &action {
        Action::BftNetworkCheckBatch { .. } | Action::BftNetworkInspectBatch { .. } => {
            Store::open_inspection(&args.dir, &args.authority, pin)?
        }
        Action::HistoryCheck { expected_head }
        | Action::ChannelReceiptAccept { expected_head, .. }
        | Action::ChannelWitnessInit { expected_head, .. }
        | Action::ChannelOwnerFinishWitness { expected_head, .. }
        | Action::ChannelOwnerInit { expected_head, .. }
        | Action::ChannelOwnerPrepare { expected_head, .. }
        | Action::ChannelOwnerSign { expected_head, .. }
        | Action::ChannelOwnerRecover { expected_head, .. }
        | Action::ChannelOwnerCombine { expected_head, .. } => Store::open_pinned(
            &args.dir,
            &args.authority,
            pin,
            Hash::from_hex(expected_head).map_err(|e| e.to_string())?,
        )?,
        _ => Store::open(&args.dir, &args.authority, pin)?,
    };
    match action {
        Action::HistoryStreamCheck { .. } | Action::HistoryStreamCompactCheck { .. } => {
            unreachable!("handled before opening a native store")
        }
        Action::BftPendingImports => {
            let commands = store
                .journal
                .contact_records
                .values()
                .filter(|r| !store.chain.ledger.imports.contains_key(&r.export))
                .map(|r| Command::Import {
                    snapshot: r.snapshot,
                    export: r.export,
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string(&commands).map_err(|e| e.to_string())?
            );
        }
        Action::BftRetainedMessages { signer_dir } => {
            let agent = bft::Agent::open(&signer_dir, &store)?;
            let messages = agent
                .journal
                .records
                .iter()
                .map(|r| r.message.clone())
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string(&messages).map_err(|e| e.to_string())?
            );
        }
        Action::BftSubmit { file } => {
            let commands: Vec<Command> = read_json(&file)?;
            let ident = store.bft_submit(commands)?;
            println!(
                "{}",
                serde_json::json!({"submission":ident,"queued":true,"block_included":false,"ledger_changed":false})
            );
        }
        Action::BftNetworkCheck { file } => {
            let envelope = read_json::<bft_network::WireEnvelope>(&file)?.expand()?;
            let ident = envelope.verify(&store)?;
            println!(
                "{}",
                serde_json::json!({"message_id":ident,"currency":pin,"region":store.chain.region,"value":envelope.value()?,"evidence":envelope.evidence,"epochs":envelope.carried_epochs(),"verified":true,"ledger_changed":false})
            );
        }
        Action::BftNetworkCheckBatch { file } => {
            let raw = storage::read_bytes(&file, MAX_BYTES)?;
            let wires: Vec<bft_network::WireEnvelope> =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let checked = bft_network::check_cold_batch(wires, &store)?;
            println!(
                "{}",
                serde_json::json!({"format":bft_network::COLD_BATCH_FORMAT,
                    "currency":pin,"region":store.chain.region,
                    "request_sha256":Hash(Sha256::digest(&raw).into()),
                    "results":checked,"verified":true,"ledger_changed":false,
                    "signing_authority":false})
            );
        }
        Action::BftNetworkInspectBatch { file } => {
            let raw = storage::read_bytes(&file, MAX_BYTES)?;
            let wires: Vec<bft_network::WireEnvelope> =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let checked = bft_network::inspect_live_batch(wires, &store)?;
            let response = serde_json::json!({"format":bft_network::LIVE_BATCH_FORMAT,
                "currency":pin,"region":store.chain.region,
                "request_sha256":Hash(Sha256::digest(&raw).into()),
                "results":checked,"verified":true,"ledger_changed":false,
                "signing_authority":false});
            let output = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
            if output.len() > MAX_BYTES {
                return Err("live network batch response exceeds bound".into());
            }
            println!("{}", String::from_utf8(output).map_err(|e| e.to_string())?);
        }
        Action::BftNetworkPack { file } => {
            let envelope: bft_network::Envelope = read_json(&file)?;
            envelope.verify(&store)?;
            println!(
                "{}",
                serde_json::to_string(&envelope.pack()?).map_err(|e| e.to_string())?
            );
        }
        Action::BftSync { file } => {
            bft_network::sync(&mut store, read_json(&file)?)?;
            println!(
                "{}",
                serde_json::json!({"currency":pin,"region":store.chain.region,"height":store.chain.height(),"state":store.chain.ledger.root()?,"finality":store.chain.finalized})
            );
        }
        Action::WalletContext => println!(
            "{}",
            serde_json::json!({
                "currency":pin,"region":store.chain.region,"fixture_only":true,"live_rld":false,
                "regions":store.journal.bootstrap.admissions.iter().map(|a| Ok(serde_json::json!({"id":a.id()?,"name":a.region}))).collect::<Result<Vec<_>>>()?
            })
        ),
        Action::WalletCoins { owner } => {
            if !owner.windows(2).all(|p| p[0] < p[1]) {
                return Err("coin owners must be ordered and unique".into());
            }
            let views = owner
                .iter()
                .map(|o| wallet::view(&store, o))
                .collect::<Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::json!({"pin": wallet::Pin::current(&store)?, "owners": views,
                "peer_wallet_reservations_known": false, "live_rld": false})
            );
        }
        Action::WalletApp { .. } => return Err("wallet app launcher was not dispatched".into()),
        Action::BftEpochProposal { checkpoint } => {
            let sid = checkpoint
                .map(|s| Hash::from_hex(&s).map_err(|e| e.to_string()))
                .transpose()?
                .or(store.chain.finalized);
            let scope =
                sid.and_then(|sid| joint_epoch::unsigned(&store.evidence, &store.trust, sid).ok());
            println!(
                "{}",
                match scope {
                    Some((proposal, previous_epochs)) =>
                        serde_json::json!({"proposal":proposal,"previous_epochs":previous_epochs}),
                    None => serde_json::json!({"proposal":null,"previous_epochs":[]}),
                }
            );
        }
        Action::BftEpochCombine { file } => println!(
            "{}",
            serde_json::to_string(&joint_epoch::combine(
                &read_json::<Vec<joint_epoch::CarriedApproval>>(&file)?,
                &store.trust,
                &store.evidence
            )?)
            .map_err(|e| e.to_string())?
        ),
        Action::BftEpochActivate { file } => {
            let envelope: bft_network::WireEnvelope = read_json(&file)?;
            let envelope = envelope.expand()?;
            envelope.verify(&store)?;
            let bft_network::Body::EpochActivation(proof) = envelope.body else {
                return Err("activation requires complete typed epoch envelope".into());
            };
            let eid = bft_network::activate(&mut store, *proof, envelope.evidence)?;
            println!("{}", serde_json::json!({"epoch":eid}));
        }
        Action::BftEpochActivateObserved {
            file,
            carried_index,
        } => {
            let raw = storage::read_bytes(&file, contact::MAX_PAYLOAD)?;
            let wire: bft_network::WireEnvelope =
                serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            let envelope = wire.expand()?;
            let observation = bft_network::activate_observed(
                &mut store,
                envelope,
                carried_index,
                Hash(Sha256::digest(&raw).into()),
            )?;
            println!(
                "{}",
                serde_json::to_string(&observation).map_err(|e| e.to_string())?
            );
        }
        Action::BftInitObservation => println!(
            "{}",
            serde_json::to_string(&bft::creation_observation(&store)?).map_err(|e| e.to_string())?
        ),
        Action::BftInstalledEpochs => {
            let context = bft::Context::current(&store)?;
            let observation = serde_json::json!({
                "format":"RLD-BFT-INSTALLED-EPOCH-OBSERVATION-V1",
                "currency":context.currency,"region":context.region,"epoch":context.epoch,
                "proofs":store.observed_installed_epochs()?,
                "fixture_only":true,"independent_freshness_qualified":false
            });
            let raw = serde_json::to_string(&observation).map_err(|e| e.to_string())?;
            if raw.len() > MAX_BYTES {
                return Err("installed epoch observation bytes bound".into());
            }
            println!("{raw}");
        }
        Action::BftContext => {
            let context = bft::Context::current(&store)?;
            let keys = context.keys(&store.trust, &store.evidence)?;
            // Known verified evidence can include a transition which the local
            // ordered journal has not activated. Expose only the exact proof
            // for the epoch actually reconstructed by native event replay.
            let mut active_epoch_proof = None;
            for proof in &store.journal.epoch_proofs {
                if proof.statement.id()? == context.epoch {
                    active_epoch_proof = Some(proof);
                    break;
                }
            }
            println!(
                "{}",
                serde_json::json!({"context":context,"keys":keys,"initial_keys":store.trust.region(store.chain.region)?.validators,"leader_round_zero":bft::leader(&context,0,&keys)?,"rules":store.trust.region(store.chain.region)?.rules,"epochs":store.evidence.epoch_proofs(store.chain.region),"active_epoch_proof":active_epoch_proof,"fixture_only":true,"independent_bft_qualified":false,"autonomous_pacemaker_qualified":false})
            );
        }
        Action::JointVoterInit {
            signer_dir,
            key,
            ready_dir,
            expected_ready_head,
            old_signer_dir,
            expected_old_head,
            file,
            observe_only,
        } => {
            let ready = joint_roles::ReadyAgent::open(&ready_dir, &store)?;
            let old = old_signer_dir
                .map(|dir| bft::Agent::open(&dir, &store))
                .transpose()?;
            let old_head = expected_old_head
                .map(|head| Hash::from_hex(&head).map_err(|e| e.to_string()))
                .transpose()?;
            let old = match (old.as_ref(), old_head) {
                (Some(agent), Some(head)) => Some((agent, head)),
                (None, None) => None,
                _ => {
                    return Err(
                        "old journal and separately retained head must be supplied together".into(),
                    )
                }
            };
            let ready_head = Hash::from_hex(&expected_ready_head).map_err(|e| e.to_string())?;
            let proof = read_json(&file)?;
            let marker = if observe_only {
                joint_roles::VoterCreation::observe(&bft::Agent::role_journal(
                    &store, key, old, &ready, ready_head, proof,
                )?)?
            } else {
                let agent = bft::Agent::create_role(
                    &signer_dir,
                    &store,
                    key,
                    old,
                    &ready,
                    ready_head,
                    proof,
                )?;
                joint_roles::VoterCreation::observe(&agent.journal)?
            };
            println!(
                "{}",
                serde_json::to_string(&marker).map_err(|e| e.to_string())?
            );
        }
        Action::JointReadyInit {
            ready_dir,
            key,
            file,
            observe_only,
        } => {
            let request = read_json(&file)?;
            let marker = if observe_only {
                joint_roles::ReadyCreation::observe(&joint_roles::ReadyAgent::initial_journal(
                    &store, key, request,
                )?)?
            } else {
                let agent = joint_roles::ReadyAgent::create(&ready_dir, &store, key, request)?;
                joint_roles::ReadyCreation::observe(&agent.journal)?
            };
            println!(
                "{}",
                serde_json::to_string(&marker).map_err(|e| e.to_string())?
            );
        }
        Action::JointReadyRecoverInit { ready_dir, file } => {
            let agent =
                joint_roles::ReadyAgent::recover_creation(&ready_dir, &store, &read_json(&file)?)?;
            println!(
                "{}",
                serde_json::to_string(&joint_roles::ReadyCreation::observe(&agent.journal)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::JointVoterRecoverInit { signer_dir, file } => {
            let agent = bft::Agent::recover_role_creation(&signer_dir, &store, &read_json(&file)?)?;
            println!(
                "{}",
                serde_json::to_string(&joint_roles::VoterCreation::observe(&agent.journal)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::JointReadyStatus { ready_dir } => {
            let agent = joint_roles::ReadyAgent::open(&ready_dir, &store)?;
            println!(
                "{}",
                serde_json::json!({"head":agent.journal.head()?,"binding":agent.journal.binding,"creation":agent.journal.creation,"scope":agent.journal.scope,"approved":agent.journal.approval.is_some(),"approval":agent.journal.approval.as_ref().map(|_| agent.journal.carried()).transpose()?,"external_rollback_anchor_qualified":false})
            );
        }
        Action::JointReadySign {
            ready_dir,
            expected_head,
            key_file,
            recover_only,
        } => {
            let mut agent = joint_roles::ReadyAgent::open(&ready_dir, &store)?;
            let result = agent.sign(
                &store,
                key_file.as_deref(),
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
                recover_only,
            )?;
            println!(
                "{}",
                serde_json::to_string(&result).map_err(|e| e.to_string())?
            );
        }
        Action::BftInit { signer_dir, key } => {
            let agent = bft::Agent::create(&signer_dir, &store, key)?;
            println!(
                "{}",
                serde_json::json!({"head":agent.journal.head()?,"binding":agent.journal.binding})
            );
        }
        Action::BftStatus { signer_dir } => {
            let (_agent, status) = bft::Agent::open_with_status(&signer_dir, &store)?;
            println!(
                "{}",
                serde_json::to_value(&status).map_err(|e| e.to_string())?
            );
        }
        Action::BftCandidate { commands, miner } => {
            let commands = commands
                .map(|p| read_json(&p))
                .transpose()?
                .unwrap_or_default();
            println!(
                "{}",
                serde_json::to_string(&store.bft_candidate(commands, miner)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::BftSign {
            file,
            signer_dir,
            expected_head,
            key_file,
            recover_only,
        } => {
            let request: bft::Request = read_json(&file)?;
            let mut agent = bft::Agent::open(&signer_dir, &store)?;
            if recover_only && !agent.journal.records.iter().any(|r| r.request == request) {
                return Err("BFT recovery cannot first-sign".into());
            }
            let signed = agent.sign(
                &store,
                request,
                key_file.as_deref(),
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&signed).map_err(|e| e.to_string())?
            );
        }
        Action::BftQuorum { file } => println!(
            "{}",
            serde_json::to_string(&bft::Quorum::combine(
                read_json(&file)?,
                &store.trust,
                &store.evidence
            )?)
            .map_err(|e| e.to_string())?
        ),
        Action::BftTimeoutCertificate { file } => println!(
            "{}",
            serde_json::to_string(&bft::TimeoutCertificate::combine(
                read_json(&file)?,
                &store.trust,
                &store.evidence
            )?)
            .map_err(|e| e.to_string())?
        ),
        Action::BftCertify { file } => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                proposal: bft::Proposal,
                prepared: bft::Quorum,
                committed: bft::Quorum,
            }
            let input: Input = read_json(&file)?;
            input.proposal.verify(&store.trust, &store.evidence)?;
            let certificate = bft::Certificate {
                prepared: input.prepared,
                committed: input.committed,
            };
            let context = input.proposal.context()?;
            certificate.verify(
                &context,
                input.proposal.snapshot.statement.id()?,
                &context.keys(&store.trust, &store.evidence)?,
            )?;
            if certificate.prepared.round != input.proposal.round {
                return Err("BFT certificate round differs from proposal".into());
            }
            let mut snapshot = *input.proposal.snapshot;
            snapshot.bft = Some(certificate);
            println!(
                "{}",
                serde_json::to_string(&snapshot).map_err(|e| e.to_string())?
            );
        }
        Action::WalletKeyCreate {
            output,
            passphrase_stdin,
        } => {
            let pass = keystore::passphrase(passphrase_stdin, true)?;
            println!(
                "{}",
                serde_json::to_string(&keystore::create(&store, &output, &pass)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::WalletKeyCheck {
            encrypted_key,
            owner,
            passphrase_stdin,
        } => {
            let pass = keystore::passphrase(passphrase_stdin, false)?;
            println!(
                "{}",
                serde_json::to_string(&keystore::check(&store, &owner, &encrypted_key, &pass)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::WalletBackup {
            wallet_dir,
            expected_wallet_head,
            encrypted_key,
            output,
            passphrase_stdin,
        } => {
            let agent = wallet_agent::Agent::open(&wallet_dir, &store)?;
            let expected = Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?;
            let pass = keystore::passphrase(passphrase_stdin, false)?;
            let head = keystore::backup(&store, &agent, expected, &encrypted_key, &output, &pass)?;
            println!(
                "{}",
                serde_json::json!({"binding":agent.journal.binding,"wallet_head":head,"complete_native_owner_journal":true,"caller_head_included":false,"fixture_only":true,"live_rld":false})
            );
        }
        Action::WalletRestore {
            wallet_dir,
            expected_wallet_head,
            file,
            passphrase_stdin,
        } => {
            let expected = Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?;
            let pass = keystore::passphrase(passphrase_stdin, false)?;
            let binding = keystore::restore(&store, &file, &wallet_dir, expected, &pass)?;
            println!(
                "{}",
                serde_json::json!({"binding":binding,"wallet_head":expected,"native_key_file":"key.enc.json","caller_head_restored":false,"external_rollback_anchor_qualified":false,"fixture_only":true,"live_rld":false})
            );
        }
        Action::Init { .. } | Action::HistoryArchive { .. } | Action::HistoryRestore { .. } => {
            unreachable!()
        }
        Action::WalletInit { owner, wallet_dir } => {
            let agent = wallet_agent::Agent::create(&wallet_dir, &store, owner)?;
            println!(
                "{}",
                serde_json::json!({"binding":agent.journal.binding,"wallet_head":agent.journal.head()?,"retain_head_separately":true})
            );
        }
        Action::WalletView {
            wallet_dir,
            expected_wallet_head,
        } => println!(
            "{}",
            serde_json::to_string(&wallet_agent::Agent::open(&wallet_dir, &store)?.view(
                &store,
                Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?
            )?)
            .map_err(|e| e.to_string())?
        ),
        Action::WalletRecover {
            wallet_dir,
            expected_wallet_head,
            intent,
        } => {
            let agent = wallet_agent::Agent::open(&wallet_dir, &store)?;
            println!(
                "{}",
                serde_json::to_string(&agent.recover(
                    &store,
                    Hash::from_hex(&intent).map_err(|e| e.to_string())?,
                    Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?
                )?)
                .map_err(|e| e.to_string())?
            );
        }
        Action::WalletPrepare {
            file,
            wallet_dir,
            expected_wallet_head,
        } => {
            let agent = wallet_agent::Agent::open(&wallet_dir, &store)?;
            let prepared = agent.prepare(
                &store,
                read_json(&file)?,
                Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&prepared).map_err(|e| e.to_string())?
            );
        }
        Action::WalletSign {
            file,
            key_file,
            encrypted_key,
            passphrase_stdin,
            recover_only,
            review,
            wallet_dir,
            expected_wallet_head,
        } => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Reviewed {
                draft: wallet::Draft,
                review_commitment: Hash,
                wallet_head: Hash,
            }
            let prepared: Reviewed = read_json(&file)?;
            let expected = Hash::from_hex(&review).map_err(|e| e.to_string())?;
            if expected != prepared.review_commitment {
                return Err("wallet separately reviewed commitment differs from file".into());
            }
            let wallet_head = Hash::from_hex(&expected_wallet_head).map_err(|e| e.to_string())?;
            if wallet_head != prepared.wallet_head {
                return Err("wallet head differs from reviewed file".into());
            }
            let mut agent = wallet_agent::Agent::open(&wallet_dir, &store)?;
            if recover_only
                && !agent
                    .journal
                    .records
                    .iter()
                    .any(|r| r.draft == prepared.draft && r.review_commitment == expected)
            {
                return Err("exact retained approval not found; recovery cannot first-sign".into());
            }
            let retained = agent
                .journal
                .records
                .iter()
                .any(|r| r.draft == prepared.draft && r.review_commitment == expected);
            if !recover_only && !retained && key_file.is_none() && encrypted_key.is_none() {
                return Err("new signing requires private key file".into());
            }
            let signed = if let Some(key) = encrypted_key
                .as_ref()
                .filter(|_| !recover_only && !retained)
            {
                let pass = keystore::passphrase(passphrase_stdin, false)?;
                agent.sign_encrypted(&store, prepared.draft, key, expected, wallet_head, &pass)?
            } else {
                let key_file = key_file.unwrap_or_else(|| PathBuf::from("/dev/null"));
                agent.sign(&store, prepared.draft, &key_file, expected, wallet_head)?
            };
            println!(
                "{}",
                serde_json::to_string(&signed).map_err(|e| e.to_string())?
            );
        }
        Action::ChannelReceiptAccept {
            file,
            expectation,
            expected_head,
        } => println!(
            "{}",
            serde_json::to_string(&store.accept_channel_receipt(
                read_json(&file)?,
                &read_json(&expectation)?,
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?
            )?)
            .map_err(|e| e.to_string())?
        ),
        Action::ChannelWitnessInit {
            witness_dir,
            witness,
            expected_head,
        } => {
            let role = channel_owner::witness::Witness::create(
                &witness_dir,
                &store,
                witness,
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::json!({"witness_head": role.head()?, "retain_head_separately": true, "independent_operations_qualified": false})
            );
        }
        Action::ChannelOwnerInit {
            owner_dir,
            owner,
            channel,
            expected_head,
            witness_dir,
            witness_key_file,
            expected_witness_head,
        } => {
            let mut witness = channel_owner::witness::Witness::open(&witness_dir, &store)?;
            let agent = channel_owner::Agent::create_witnessed(
                &owner_dir,
                &store,
                Hash::from_hex(&channel).map_err(|e| e.to_string())?,
                owner,
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
                &mut witness,
                (
                    &witness_key_file,
                    Hash::from_hex(&expected_witness_head).map_err(|e| e.to_string())?,
                ),
            )?;
            println!(
                "{}",
                serde_json::json!({"binding":agent.binding(),"owner_head":agent.head()?,"initial_request":agent.initial_request(&store)?,"witness_head":witness.head()?,"retain_heads_separately":true,"first_signed":false,"live_rld":false,"independent_operations_qualified":false})
            );
        }
        Action::ChannelOwnerPrepare {
            owner_dir,
            file,
            expected_owner_head,
            expected_head,
            witness_dir,
            expected_witness_head,
        } => {
            let request: channel_owner::Request = read_json(&file)?;
            let witness = channel_owner::witness::Witness::open(&witness_dir, &store)?;
            let agent = channel_owner::Agent::open(&owner_dir, &store)?;
            let review = agent.prepare_witnessed(
                &store,
                &request,
                (
                    Hash::from_hex(&expected_owner_head).map_err(|e| e.to_string())?,
                    Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
                ),
                &witness,
                Hash::from_hex(&expected_witness_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::json!({"binding":agent.binding(),"request":request,"review":review,"owner_head":agent.head()?,"witness_head":witness.head()?,"signed_or_reserved":false,"live_rld":false})
            );
        }
        Action::ChannelOwnerSign {
            owner_dir,
            file,
            review,
            expected_owner_head,
            expected_head,
            witness_dir,
            expected_witness_head,
            key_file,
            witness_key_file,
        } => {
            let mut witness = channel_owner::witness::Witness::open(&witness_dir, &store)?;
            let input = channel_owner::witness::Reviewed {
                request: read_json(&file)?,
                review: Hash::from_hex(&review).map_err(|e| e.to_string())?,
                owner_head: Hash::from_hex(&expected_owner_head).map_err(|e| e.to_string())?,
                native_head: Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            };
            let response = channel_owner::Agent::open(&owner_dir, &store)?.sign_witnessed(
                &store,
                input,
                &key_file,
                &mut witness,
                &witness_key_file,
                Hash::from_hex(&expected_witness_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|e| e.to_string())?
            );
        }
        Action::ChannelOwnerRecover {
            owner_dir,
            file,
            review,
            expected_owner_head,
            expected_head,
            witness_dir,
            expected_witness_head,
        } => {
            let mut witness = channel_owner::witness::Witness::open(&witness_dir, &store)?;
            let input = channel_owner::witness::Reviewed {
                request: read_json(&file)?,
                review: Hash::from_hex(&review).map_err(|e| e.to_string())?,
                owner_head: Hash::from_hex(&expected_owner_head).map_err(|e| e.to_string())?,
                native_head: Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            };
            let response = channel_owner::Agent::open(&owner_dir, &store)?.recover_witnessed(
                &store,
                &input,
                &mut witness,
                Hash::from_hex(&expected_witness_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|e| e.to_string())?
            );
        }
        Action::ChannelOwnerFinishWitness {
            owner_dir,
            file,
            review,
            expected_owner_head,
            expected_head,
            witness_dir,
            expected_witness_head,
            witness_key_file,
        } => {
            let mut witness = channel_owner::witness::Witness::open(&witness_dir, &store)?;
            let input = channel_owner::witness::Reviewed {
                request: read_json(&file)?,
                review: Hash::from_hex(&review).map_err(|e| e.to_string())?,
                owner_head: Hash::from_hex(&expected_owner_head).map_err(|e| e.to_string())?,
                native_head: Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            };
            let response = channel_owner::Agent::open(&owner_dir, &store)?.finish_witness(
                &store,
                &input,
                &mut witness,
                &witness_key_file,
                Hash::from_hex(&expected_witness_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|e| e.to_string())?
            );
        }
        Action::ChannelOwnerCombine {
            file,
            expected_head,
        } => {
            let combined = channel_owner::combine(
                &store,
                read_json(&file)?,
                Hash::from_hex(&expected_head).map_err(|e| e.to_string())?,
            )?;
            println!(
                "{}",
                serde_json::to_string(&combined).map_err(|e| e.to_string())?
            );
        }
        Action::WalletReceipt { file } => println!(
            "{}",
            serde_json::to_string(&wallet::receipt(&store, read_json(&file)?)?)
                .map_err(|e| e.to_string())?
        ),
        Action::WalletCombine { file } => println!(
            "{}",
            serde_json::to_string(&wallet::combine(&store, read_json(&file)?)?)
                .map_err(|e| e.to_string())?
        ),
        Action::HistoryHead | Action::HistoryCheck { .. } => {
            let manifest = history::manifest(&args.dir)?;
            println!(
                "{}",
                serde_json::json!({
                    "format":manifest.format,"history_head":manifest.head()?,
                    "sealed_event_pages":store.journal.event_prefix.len(),
                    "retained_tail_events":store.journal.events.len(),
                    "event_page_bound":history::PAGE_EVENTS,
                    "currency":pin,"region":store.chain.region,"height":store.chain.height(),
                    "tip":store.chain.tip()?,"state":store.chain.ledger.root()?,
                    "finality":store.chain.finalized,"validator_epoch":store.chain.epoch,
                    "import_commitment":id("native-history-imports",&store.chain.ledger.imports)?,
                    "permanent_import_entries":store.chain.ledger.imports.len(),
                    "logical_native_replay_complete":true,"retain_head_separately":true,
                    "independent_latest_state_anchor_qualified":false,
                    "long_history_qualified":false,"fixture_only":true,"live_rld":false
                })
            );
        }
        Action::Status => {
            let bft = bft::is_profile(&store.trust.region(store.chain.region)?.rules);
            println!(
                "{}",
                serde_json::json!({"region":store.chain.region,"currency":pin,"height":store.chain.height(),"tip":store.chain.tip()?,"state":store.chain.ledger.root()?,"finality":store.chain.finalized,"validator_epoch":store.chain.epoch,"ledger":store.chain.ledger,"quarantined_regions":store.safety.regions,"incident_ids":store.conflicts.iter().map(|p|p.id()).collect::<Result<Vec<_>>>()?,"exposure":store.safety.exposure(&store.chain,&store.evidence)?,"fixture_only":true,"live_rld":false,"source_http_required":false,"consensus":if bft {"explicitly admitted four-validator ground profile: three-vote prepare/commit quorums and certified view changes; no autonomous pacemaker or independent BFT qualification"} else {"append-only PoW history with explicit unanimous checkpoint; no BFT view changes"}})
            );
        }
        Action::StateProof {
            checkpoint,
            collection,
            key,
        } => {
            let sid = Hash::from_hex(&checkpoint).map_err(|e| e.to_string())?;
            let collection = state_proof::Collection::parse(&collection)?;
            let key = Hash::from_hex(&key).map_err(|e| e.to_string())?;
            store
                .safety
                .check_region(store.evidence.snapshot(sid)?.statement.region)?;
            let proof = store
                .evidence
                .prove_state(sid, collection, key, &store.trust)?;
            println!(
                "{}",
                serde_json::to_string(&proof).map_err(|e| e.to_string())?
            );
        }
        Action::StateProofCheck {
            checkpoint,
            collection,
            key,
            file,
        } => {
            let sid = Hash::from_hex(&checkpoint).map_err(|e| e.to_string())?;
            let collection = state_proof::Collection::parse(&collection)?;
            let key = Hash::from_hex(&key).map_err(|e| e.to_string())?;
            store
                .safety
                .check_region(store.evidence.snapshot(sid)?.statement.region)?;
            let proof = read_json::<state_proof::Proof>(&file)?;
            let value =
                store
                    .evidence
                    .check_state_proof(sid, collection, key, &proof, &store.trust)?;
            println!(
                "{}",
                serde_json::json!({"checkpoint":sid,"collection":collection,"key":key,
                "record":value,"native_certified_state_verified":true,"ledger_changed":false,
                "current_spendability_authorized":false,"fixture_only":true,"live_rld":false})
            );
        }
        Action::Mine { miner, commands } => {
            let commands = commands
                .map(|p| read_json::<Vec<Command>>(&p))
                .transpose()?
                .unwrap_or_default();
            let mut block = store.template(commands, miner)?;
            mine(&mut block)?;
            store.accept(block.clone())?;
            println!(
                "{}",
                serde_json::to_string(&block).map_err(|e| e.to_string())?
            );
        }
        Action::Evidence { file } => {
            store.add_evidence(read_json(&file)?)?;
            println!(
                "{}",
                serde_json::json!({"verified_snapshots":store.journal.evidence.snapshots.len(),"ledger_changed":false})
            );
        }
        Action::Finalize { file } => {
            let sid = store.finalize(read_json(&file)?)?;
            println!("{}", serde_json::json!({"installed_checkpoint":sid}));
        }
        Action::Incident { file } => {
            let iid = store.observe_conflict(read_json::<
                rld_regional_ledger_candidate::conflict::Incident,
            >(&file)?)?;
            println!(
                "{}",
                serde_json::json!({"durable_incident":iid,"quarantined_regions":store.safety.regions,"ledger_changed":false})
            );
        }
        Action::RecoverIncident { .. } => println!(
            "{}",
            serde_json::json!({"recovered_retained_incident":true,"quarantined_regions":store.safety.regions})
        ),
        Action::Incidents => println!(
            "{}",
            serde_json::to_string(&store.conflicts).map_err(|e| e.to_string())?
        ),
        Action::Proof => println!(
            "{}",
            serde_json::to_string(&store.journal.evidence).map_err(|e| e.to_string())?
        ),
        Action::ContactNode { .. } => unreachable!(),
        Action::ContactExport { export } => println!(
            "{}",
            String::from_utf8(
                store.contact_export(Hash::from_hex(&export).map_err(|e| e.to_string())?)?
            )
            .map_err(|e| e.to_string())?
        ),
        Action::ContactApply { file, miner } => {
            let bytes =
                rld_regional_ledger_candidate::storage::read_bytes(&file, contact::MAX_FRAME)?;
            println!(
                "{}",
                serde_json::to_string(&store.contact_apply(&bytes, miner)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::ContactOutgoing => {
            let mut offers = vec![];
            if let Some(sid) = store.chain.finalized {
                for (eid, record) in &store.chain.ledger.exports {
                    if store.evidence.export(sid, *eid).is_ok() {
                        offers.push(serde_json::json!({"export":eid,"destination":record.destination,"snapshot":sid}));
                    }
                }
            }
            println!(
                "{}",
                serde_json::json!({"currency":pin,"region":store.chain.region,"offers":offers,"all_offers_require_native_contact_export_validation":true})
            );
        }
        Action::ContactStatus => {
            let contacts = store
                .journal
                .contact_records
                .keys()
                .map(|id| store.contact_status(*id))
                .collect::<Result<Vec<_>>>()?;
            println!(
                "{}",
                serde_json::json!({"currency":pin,"region":store.chain.region,"local_height":store.chain.height(),"contacts":contacts,"source_http_required":false})
            );
        }
        Action::ContactResume { message, miner } => println!(
            "{}",
            serde_json::to_string(
                &store
                    .contact_fulfill(Hash::from_hex(&message).map_err(|e| e.to_string())?, miner)?
            )
            .map_err(|e| e.to_string())?
        ),
        Action::Statement => println!(
            "{}",
            serde_json::to_string(&store.snapshot_request()?).map_err(|e| e.to_string())?
        ),
        Action::ProposeEpoch { validators } => println!(
            "{}",
            serde_json::to_string(&store.epoch_request(read_json(&validators)?)?)
                .map_err(|e| e.to_string())?
        ),
        Action::InstallEpoch { file } => {
            let eid = store.install_epoch(read_json(&file)?)?;
            println!(
                "{}",
                serde_json::json!({"installed_validator_epoch":eid,"ledger_changed":false})
            );
        }
        Action::SignerInit { signer_dir, key } => {
            let agent = signer::Agent::create(&signer_dir, &store, key)?;
            println!(
                "{}",
                serde_json::json!({"binding":agent.journal.binding,"lock_head":agent.journal.head()?,"retain_head_separately":true})
            );
        }
        Action::SignerRecoverHandoff {
            signer_dir,
            file,
            expected_lock,
        } => {
            let agent = signer::Agent::open(&signer_dir, &store)?;
            println!(
                "{}",
                serde_json::to_string(&agent.recover_handoff(
                    &store,
                    &read_json(&file)?,
                    Hash::from_hex(&expected_lock).map_err(|e| e.to_string())?
                )?)
                .map_err(|e| e.to_string())?
            );
        }
        Action::SignerStatus { signer_dir } => {
            let agent = signer::Agent::open(&signer_dir, &store)?;
            let handoffs = agent
                .journal
                .records
                .iter()
                .filter_map(|record| {
                    if let signer::Request::Handoff { proposal, .. } = &record.request {
                        Some(proposal.statement.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::json!({"binding":agent.journal.binding,"lock_head":agent.journal.head()?,"votes":agent.journal.records.len(),"handoff_statements":handoffs,"local_status_is_not_an_external_rollback_anchor":true})
            );
        }
        Action::SignCheckpoint {
            signer_dir,
            key_file,
            expected_lock,
        } => {
            let expected = Hash::from_hex(&expected_lock).map_err(|e| e.to_string())?;
            let mut agent = signer::Agent::open(&signer_dir, &store)?;
            println!(
                "{}",
                serde_json::to_string(&agent.checkpoint(&store, &key_file, expected)?)
                    .map_err(|e| e.to_string())?
            );
        }
        Action::SignHandoff {
            signer_dir,
            key_file,
            expected_lock,
            file,
        } => {
            let expected = Hash::from_hex(&expected_lock).map_err(|e| e.to_string())?;
            let mut agent = signer::Agent::open(&signer_dir, &store)?;
            println!(
                "{}",
                serde_json::to_string(&agent.handoff(
                    &store,
                    read_json(&file)?,
                    &key_file,
                    expected
                )?)
                .map_err(|e| e.to_string())?
            );
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("regional candidate rejected: {error}");
        std::process::exit(1);
    }
}
