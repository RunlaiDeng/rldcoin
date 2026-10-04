//! Public-seed, no-value construction for the separate read-only stream archive.
//! No ordinary node/wallet custody is opened and no serialized ledger is adopted.
use clap::Parser;
use ed25519_dalek::SigningKey;
use rld_core::{sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_regional_ledger_candidate::{
    storage::read_json,
    stream_archive::{Binding, Record},
    stream_replay::{Cursor, Record as NativeRecord},
    *,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(
    about = "Public no-value fixture only: complete native replay, no ordinary/BFT/custody upgrade"
)]
struct Args {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    root: PathBuf,
    #[arg(long, default_value_t = 200000)]
    payments: u64,
}
fn check(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
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
fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| e.to_string())
}
fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut file = private_file(path)?;
    serde_json::to_writer(&mut file, value).map_err(|e| e.to_string())?;
    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
fn advance(
    chain: &mut Chain,
    trust: &Trust,
    evidence: &VerifiedEvidence,
    commands: Vec<Command>,
) -> Result<()> {
    let mut block = chain.template(commands, public(10), trust, evidence)?;
    mine(&mut block)?;
    chain.accept(block, trust, evidence)
}
fn finalize(
    chain: &mut Chain,
    trust: &Trust,
    evidence: &mut VerifiedEvidence,
    start: u8,
) -> Result<Hash> {
    let statement = chain.statement(trust)?;
    let mut approvals = (start..start + 4)
        .map(|seed| {
            Ok(Approval {
                key: public(seed),
                signature: sign(seed, &statement.bytes()?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    approvals.sort_by(|a, b| a.key.cmp(&b.key));
    let checkpoint = evidence.add(
        Snapshot {
            base: None,
            bft: None,
            statement,
            approvals,
            blocks: chain.blocks.clone(),
            epochs: vec![],
        },
        trust,
    )?;
    chain.install(checkpoint, evidence)?;
    Ok(checkpoint)
}
#[allow(clippy::too_many_arguments)] // Complete signed fixture owner intent fields.
fn intent(
    region: Hash,
    height: u64,
    inputs: Vec<Hash>,
    outputs: Vec<Payment>,
    destination: Option<Hash>,
    remote: Option<Payment>,
    fee: u128,
    destination_fee: u128,
    seed: u8,
    trust: &Trust,
) -> Result<SignedIntent> {
    let intent = Intent {
        currency: trust.currency()?,
        region,
        inputs,
        outputs,
        fee: Amount(fee),
        destination,
        remote,
        destination_fee: Amount(destination_fee),
        valid_through: height + 1,
    };
    let approvals = vec![Approval {
        key: public(seed),
        signature: sign(seed, &intent.bytes()?)?,
    }];
    Ok(SignedIntent { intent, approvals })
}
fn coin(ledger: &Ledger, owner: u8, amount: Amount) -> Result<Hash> {
    ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(owner) && c.payment.amount == amount)
        .map(|(key, _)| *key)
        .ok_or_else(|| "exact fixture owner coin absent".into())
}
fn audit(earth: &Ledger, proxima: &Ledger) -> Result<(Amount, Amount, Amount)> {
    let issued = earth
        .minted
        .checked_add(proxima.minted)
        .map_err(|e| e.to_string())?;
    let mut liquid = Amount::ZERO;
    let mut pending = Amount::ZERO;
    for c in earth.coins.values().chain(proxima.coins.values()) {
        liquid = liquid
            .checked_add(c.payment.amount)
            .map_err(|e| e.to_string())?;
    }
    for (source, destination) in [(earth, proxima), (proxima, earth)] {
        for (key, export) in &source.exports {
            if !destination.imports.contains_key(key) {
                pending = pending
                    .checked_add(export.recipient.amount)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    check(
        issued == liquid.checked_add(pending).map_err(|e| e.to_string())?,
        "fixture native conservation",
    )?;
    Ok((issued, liquid, pending))
}
struct Archive {
    file: File,
    bytes: u64,
    records: u64,
    binding: Binding,
}
impl Archive {
    fn append(&mut self, record: Record) -> Result<()> {
        let line = record.line()?;
        let total = self
            .bytes
            .checked_add(line.len() as u64)
            .ok_or("archive length overflow")?;
        check(
            total <= stream_replay::MAX_ARCHIVE_BYTES,
            "private stream archive capacity refusal",
        )?;
        self.file.write_all(&line).map_err(|e| e.to_string())?;
        self.bytes = total;
        self.records += 1;
        Ok(())
    }
    fn native(&mut self, record: NativeRecord) -> Result<()> {
        self.append(Record::from_native(record, &self.binding)?)
    }
    fn block(
        &mut self,
        cursor: &mut Cursor,
        commands: Vec<Command>,
        trust: &Trust,
        evidence: &VerifiedEvidence,
    ) -> Result<()> {
        let mut block = cursor.template(commands, public(10), trust, evidence)?;
        mine(&mut block)?;
        cursor.accept(&block, trust, evidence)?;
        self.native(NativeRecord::Block {
            block: Box::new(block),
        })
    }
}
fn run() -> Result<()> {
    let args = Args::parse();
    let started = Instant::now();
    check(
        (1..=200000).contains(&args.payments),
        "fixture payment count bound",
    )?;
    let bootstrap: Bootstrap = read_json(&args.bootstrap)?;
    let trust = Trust::verify(&bootstrap, &public(1), bootstrap.currency.id()?)?;
    check(
        bootstrap.currency.cap == Amount(300)
            && bootstrap.currency.block_reward == Amount(100)
            && bootstrap.currency.maturity == 2,
        "exact public no-value issuance fixture required",
    )?;
    for (label, start) in [("earth", 2u8), ("proxima", 22u8)] {
        let mut keys = (start..start + 4).map(public).collect::<Vec<_>>();
        keys.sort();
        let admission = trust.region(trust.named(label)?)?;
        check(
            admission.rules == "RLD-REGIONAL-FIXTURE-V1" && admission.validators == keys,
            "exact initial unanimous public fixture admission required",
        )?;
    }
    check(
        !args.root.exists() && !args.root.is_symlink(),
        "fresh private fixture root required; preserve interrupted roots",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&args.root)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir(&args.root).map_err(|e| e.to_string())?;
    }
    save(
        &args.root.join("GENERATING"),
        &serde_json::json!({"fixture_only":true,"live_rld":false,"payments":args.payments}),
    )?;
    save(&args.root.join("bootstrap.json"), &bootstrap)?;
    let mut earth = Chain::new(trust.named("earth")?, &trust)?;
    let mut proxima = Chain::new(trust.named("proxima")?, &trust)?;
    let mut evidence = VerifiedEvidence::default();
    for _ in 0..4 {
        advance(&mut earth, &trust, &evidence, vec![])?;
        audit(&earth.ledger, &proxima.ledger)?;
    }
    let initial = finalize(&mut earth, &trust, &mut evidence, 2)?;
    let original = coin(&earth.ledger, 10, Amount(100))?;
    let exported = intent(
        earth.region,
        earth.height(),
        vec![original],
        vec![Payment {
            owner: public(10),
            amount: Amount(19),
        }],
        Some(proxima.region),
        Some(Payment {
            owner: public(11),
            amount: Amount(80),
        }),
        1,
        2,
        10,
        &trust,
    )?;
    let outbound = exported.intent.id()?;
    advance(
        &mut earth,
        &trust,
        &evidence,
        vec![Command::Spend(Box::new(exported))],
    )?;
    audit(&earth.ledger, &proxima.ledger)?;
    let source = finalize(&mut earth, &trust, &mut evidence, 2)?;
    advance(
        &mut proxima,
        &trust,
        &evidence,
        vec![Command::Import {
            snapshot: source,
            export: outbound,
        }],
    )?;
    audit(&earth.ledger, &proxima.ledger)?;
    for _ in 0..2 {
        advance(&mut proxima, &trust, &evidence, vec![])?;
    }
    let recipient = finalize(&mut proxima, &trust, &mut evidence, 22)?;
    let returned = intent(
        proxima.region,
        proxima.height(),
        vec![coin(&proxima.ledger, 11, Amount(78))?],
        vec![Payment {
            owner: public(11),
            amount: Amount(18),
        }],
        Some(earth.region),
        Some(Payment {
            owner: public(12),
            amount: Amount(60),
        }),
        0,
        1,
        11,
        &trust,
    )?;
    let return_id = returned.intent.id()?;
    advance(
        &mut proxima,
        &trust,
        &evidence,
        vec![Command::Spend(Box::new(returned))],
    )?;
    audit(&earth.ledger, &proxima.ledger)?;
    let return_checkpoint = finalize(&mut proxima, &trust, &mut evidence, 22)?;
    let raw = Evidence {
        snapshots: [initial, source, recipient, return_checkpoint]
            .into_iter()
            .map(|sid| evidence.snapshot(sid).cloned())
            .collect::<Result<Vec<_>>>()?,
    };
    let archive_path = args.root.join("history.compact.jsonl");
    let binding = Binding::new(&trust, "earth")?;
    let mut archive = Archive {
        file: private_file(&archive_path)?,
        bytes: 0,
        records: 0,
        binding: binding.clone(),
    };
    archive.append(Record::Binding { binding })?;
    archive.native(NativeRecord::Evidence { evidence: raw })?;
    let mut cursor = Cursor::new(earth.region, &trust)?;
    cursor.observe_evidence(&trust, &evidence)?;
    for block in &earth.blocks {
        cursor.accept(block, &trust, &evidence)?;
        archive.native(NativeRecord::Block {
            block: Box::new(block.clone()),
        })?;
    }
    cursor.install(source, &trust, &evidence)?;
    archive.native(NativeRecord::Finalize { checkpoint: source })?;
    let mut owner = 10;
    let mut input = coin(cursor.ledger(), owner, Amount(100))?;
    for payment in 1..=args.payments {
        let next = if owner == 20 { 21 } else { 20 };
        let signed = intent(
            earth.region,
            cursor.head()?.observation.height,
            vec![input],
            vec![Payment {
                owner: public(next),
                amount: Amount(100),
            }],
            None,
            None,
            0,
            0,
            owner,
            &trust,
        )?;
        archive.block(
            &mut cursor,
            vec![Command::Spend(Box::new(signed))],
            &trust,
            &evidence,
        )?;
        audit(cursor.ledger(), &proxima.ledger)?;
        input = coin(cursor.ledger(), next, Amount(100))?;
        owner = next;
        if payment % 1024 == 0 {
            println!(
                "{}",
                serde_json::json!({"phase":"native construction","payments":payment,
                "height":cursor.head()?.observation.height,"archive_bytes":archive.bytes,
                "elapsed_seconds":started.elapsed().as_secs_f64()})
            );
        }
    }
    archive.block(
        &mut cursor,
        vec![Command::Import {
            snapshot: return_checkpoint,
            export: return_id,
        }],
        &trust,
        &evidence,
    )?;
    let imported_height = cursor.head()?.observation.height;
    audit(cursor.ledger(), &proxima.ledger)?;
    for _ in 0..2 {
        archive.block(&mut cursor, vec![], &trust, &evidence)?;
    }
    let returned_coin = coin(cursor.ledger(), 12, Amount(59))?;
    let signed = intent(
        earth.region,
        cursor.head()?.observation.height,
        vec![returned_coin],
        vec![Payment {
            owner: public(20),
            amount: Amount(59),
        }],
        None,
        None,
        0,
        0,
        12,
        &trust,
    )?;
    archive.block(
        &mut cursor,
        vec![Command::Spend(Box::new(signed))],
        &trust,
        &evidence,
    )?;
    let (issued, liquid, pending) = audit(cursor.ledger(), &proxima.ledger)?;
    check(
        !cursor.ledger().coins.contains_key(&original)
            && cursor.ledger().imports.get(&return_id) == Some(&return_checkpoint)
            && cursor.ledger().exports.contains_key(&outbound),
        "original debit and permanent import identity",
    )?;
    check(
        cursor
            .template(
                vec![Command::Import {
                    snapshot: return_checkpoint,
                    export: return_id,
                }],
                public(10),
                &trust,
                &evidence,
            )
            .is_err(),
        "duplicate returned import was accepted",
    )?;
    let head = cursor.head()?;
    archive.file.sync_all().map_err(|e| e.to_string())?;
    save(&args.root.join("head.json"), &head)?;
    save(
        &args.root.join("construction.json"),
        &serde_json::json!({
            "format":"RLD-NATIVE-COMPACT-STREAM-FIXTURE-V1","fixture_only":true,"live_rld":false,
            "native_implementation":implementation()?,"currency":trust.currency()?,"head":head,
            "expected_head":head.id()?,"owner_payments":args.payments+1,"archive_bytes":archive.bytes,
            "archive_records":archive.records,"returned_import_height":imported_height,
            "returned_mature_payment_height":head.observation.height,"issued":issued,"liquid":liquid,"pending":pending,
            "original_debit_never_released":true,"retained_observations":cursor.retained_observations(),
            "generation_seconds":started.elapsed().as_secs_f64(),"all_native_transitions_and_conservation_checked":true,
            "cold_replay_completed":false,"ordinary_node_upgraded":false,"bft_or_epoch_qualified":false,
            "late_onward_export_qualified":false,"issuance_era_qualified":false,"independent_custody_qualified":false,
            "incident_quarantine_reconciled":false,"physical_route_qualified":false
        }),
    )?;
    File::open(&args.root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    std::fs::remove_file(args.root.join("GENERATING")).map_err(|e| e.to_string())?;
    File::open(&args.root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"phase":"construction complete","height":head.observation.height,
        "owner_payments":args.payments+1,"archive_bytes":archive.bytes,"expected_head":head.id()?,
        "cold_replay_completed":false,"fixture_only":true,"live_rld":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
