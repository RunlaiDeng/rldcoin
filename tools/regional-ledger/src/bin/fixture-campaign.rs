//! Public deterministic seeds only. Exercises separate native CLI processes.
use ed25519_dalek::SigningKey;
use rld_core::{sign_bytes, AdmissionHash32 as Hash, Amount};
use rld_regional_ledger_candidate::{storage::Journal, *};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command as Process,
};
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn signature(seed: u8, bytes: &[u8]) -> Result<String> {
    sign_bytes(&hex::encode([seed; 32]), bytes)
}
fn seeds(region: &str) -> Vec<u8> {
    let first = match region {
        "earth" => 2,
        "proxima" => 22,
        "andromeda" => 42,
        _ => panic!("fixture region"),
    };
    let mut seeds = (first..first + 4).collect::<Vec<_>>();
    seeds.sort_by_key(|s| public(*s));
    seeds
}
fn save<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    fs::write(path, serde_json::to_vec(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
struct Campaign {
    root: PathBuf,
    binary: PathBuf,
    bootstrap: Bootstrap,
    pin: Hash,
    checks: Vec<Value>,
    calls: usize,
    lock_heads: BTreeMap<String, Hash>,
    validator_seeds: BTreeMap<String, Vec<u8>>,
}
impl Campaign {
    fn cli(&mut self, region: &str, args: &[String], success: bool) -> Result<Value> {
        let output = Process::new(&self.binary)
            .arg("--dir")
            .arg(self.root.join(region))
            .arg("--authority")
            .arg(public(1))
            .arg("--currency")
            .arg(self.pin.to_hex())
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        self.calls += 1;
        if output.status.success() != success {
            return Err(format!(
                "CLI {region} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        if success {
            serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
        } else {
            Ok(json!({"rejected":true,"reason":String::from_utf8_lossy(&output.stderr).trim()}))
        }
    }
    fn chain(&self, region: &str) -> Result<Chain> {
        let journal: Journal =
            rld_regional_ledger_candidate::history::read_journal(&self.root.join(region))?;
        Ok(journal.replay(&public(1), self.pin)?.2)
    }
    fn audit(&mut self, phase: &str) -> Result<()> {
        let chains = [
            self.chain("earth")?,
            self.chain("proxima")?,
            self.chain("andromeda")?,
        ];
        let (issued, liquid, escrow, pending) = conservation_with_escrow(&chains)?;
        self.checks.push(json!({"phase":phase,"issued":issued,"liquid_including_immature_and_fees":liquid,"channel_escrow_and_reserves":escrow,"pending_exports":pending,"conserved":true}));
        Ok(())
    }
    fn mine(&mut self, region: &str, commands: Vec<Command>) -> Result<()> {
        let path = self.root.join("commands.json");
        save(&path, &commands)?;
        self.cli(
            region,
            &[
                "mine".into(),
                "--miner".into(),
                public(10),
                "--commands".into(),
                path.display().to_string(),
            ],
            true,
        )?;
        self.audit(&format!("{region}:block"))
    }
    fn signer_name(region: &str, seed: u8) -> String {
        format!("{region}-{seed}")
    }
    fn signer_dir(&self, region: &str, seed: u8) -> PathBuf {
        self.root
            .join("signers")
            .join(Self::signer_name(region, seed))
    }
    fn key_file(&self, region: &str, seed: u8) -> PathBuf {
        self.root
            .join("public-fixture-key-inputs")
            .join(format!("{}.json", Self::signer_name(region, seed)))
    }
    fn save_pins(&self) -> Result<()> {
        save(
            &self.root.join("caller-retained-lock-heads.json"),
            &self.lock_heads,
        )
    }
    fn init_signer(&mut self, region: &str, seed: u8) -> Result<()> {
        let path = self.key_file(region, seed);
        save(&path, &json!({"secret_key":hex::encode([seed;32])}))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        let result = self.cli(
            region,
            &[
                "signer-init".into(),
                "--signer-dir".into(),
                self.signer_dir(region, seed).display().to_string(),
                "--key".into(),
                public(seed),
            ],
            true,
        )?;
        self.lock_heads.insert(
            Self::signer_name(region, seed),
            serde_json::from_value(result["lock_head"].clone()).map_err(|e| e.to_string())?,
        );
        self.save_pins()
    }
    fn signer_args(&self, region: &str, seed: u8, action: &str) -> Result<Vec<String>> {
        Ok(vec![
            action.into(),
            "--signer-dir".into(),
            self.signer_dir(region, seed).display().to_string(),
            "--key-file".into(),
            self.key_file(region, seed).display().to_string(),
            "--expected-lock".into(),
            self.lock_heads
                .get(&Self::signer_name(region, seed))
                .ok_or("missing externally retained fixture head")?
                .to_hex(),
        ])
    }
    fn vote(&mut self, region: &str, seed: u8, proposal: Option<&Path>) -> Result<Approval> {
        let mut args = self.signer_args(
            region,
            seed,
            if proposal.is_some() {
                "sign-handoff"
            } else {
                "sign-checkpoint"
            },
        )?;
        if let Some(path) = proposal {
            args.extend(["--file".into(), path.display().to_string()]);
        }
        let result = self.cli(region, &args, true)?;
        self.lock_heads.insert(
            Self::signer_name(region, seed),
            serde_json::from_value(result["lock_head"].clone()).map_err(|e| e.to_string())?,
        );
        self.save_pins()?;
        serde_json::from_value(result["approval"].clone()).map_err(|e| e.to_string())
    }
    fn certify(&mut self, region: &str) -> Result<Hash> {
        let value = self.cli(region, &["statement".into()], true)?;
        let mut snapshot: Snapshot = serde_json::from_value(value).map_err(|e| e.to_string())?;
        for seed in self
            .validator_seeds
            .get(region)
            .ok_or("missing fixture validators")?
            .clone()
        {
            snapshot.approvals.push(self.vote(region, seed, None)?);
        }
        let sid = snapshot.statement.id()?;
        let path = self.root.join("checkpoint.json");
        save(&path, &snapshot)?;
        self.cli(
            region,
            &[
                "finalize".into(),
                "--file".into(),
                path.display().to_string(),
            ],
            true,
        )?;
        self.audit(&format!("{region}:checkpoint with durable signer locks"))?;
        Ok(sid)
    }
    fn stale_signer_drill(&mut self, region: &str, seed: u8, backup: &[u8]) -> Result<()> {
        let path = self.signer_dir(region, seed).join("signer.json");
        let current = fs::read(&path).map_err(|e| e.to_string())?;
        fs::write(&path, backup).map_err(|e| e.to_string())?;
        let args = self.signer_args(region, seed, "sign-checkpoint")?;
        let rejected = self.cli(region, &args, false)?;
        if !rejected["reason"]
            .as_str()
            .unwrap_or("")
            .contains("caller-retained")
        {
            return Err("stale signer failure was not external-head refusal".into());
        }
        fs::write(path, current).map_err(|e| e.to_string())?;
        self.audit(
            "stale signer backup rejected by retained latest head; exact current journal restored",
        )
    }
    fn rotate_earth(&mut self) -> Result<Hash> {
        let mut new = (62..66).collect::<Vec<_>>();
        new.sort_by_key(|s| public(*s));
        for seed in &new {
            self.init_signer("earth", *seed)?;
        }
        let validators = self.root.join("next-validators.json");
        save(
            &validators,
            &new.iter().map(|s| public(*s)).collect::<Vec<_>>(),
        )?;
        let value = self.cli(
            "earth",
            &[
                "propose-epoch".into(),
                "--validators".into(),
                validators.display().to_string(),
            ],
            true,
        )?;
        let unsigned: epoch::Transition =
            serde_json::from_value(value).map_err(|e| e.to_string())?;
        let path = self.root.join("epoch-proposal.json");
        save(&path, &unsigned)?;
        let mut proof = unsigned;
        let old = self.validator_seeds["earth"].clone();
        for seed in &old {
            proof
                .old_approvals
                .push(self.vote("earth", *seed, Some(&path))?);
        }
        for seed in &new {
            proof
                .new_approvals
                .push(self.vote("earth", *seed, Some(&path))?);
        }
        let args = self.signer_args("earth", old[0], "sign-checkpoint")?;
        let refusal = self.cli("earth", &args, false)?;
        if !refusal["reason"].as_str().unwrap_or("").contains("sealed") {
            return Err("old era was not sealed before activation".into());
        }
        let mut missing = proof.clone();
        missing.new_approvals.pop();
        save(&path, &missing)?;
        let state = self.chain("earth")?.ledger.root()?;
        self.cli(
            "earth",
            &[
                "install-epoch".into(),
                "--file".into(),
                path.display().to_string(),
            ],
            false,
        )?;
        if state != self.chain("earth")?.ledger.root()? {
            return Err("incomplete handoff changed ledger".into());
        }
        save(&path, &proof)?;
        self.cli(
            "earth",
            &[
                "install-epoch".into(),
                "--file".into(),
                path.display().to_string(),
            ],
            true,
        )?;
        if state != self.chain("earth")?.ledger.root()? {
            return Err("validator handoff changed ledger".into());
        }
        self.validator_seeds.insert("earth".into(), new);
        self.audit(
            "joint old/new four-signature epoch activated with same currency and value state",
        )?;
        proof.statement.id()
    }
    fn carry(&mut self, from: &str, to: &str) -> Result<()> {
        let proof = self.cli(from, &["proof".into()], true)?;
        let path = self.root.join("contact-evidence.json");
        save(&path, &proof)?;
        self.cli(
            to,
            &[
                "evidence".into(),
                "--file".into(),
                path.display().to_string(),
            ],
            true,
        )?;
        self.audit(&format!("contact:{from}->{to}"))
    }
    fn spend(
        &self,
        region: &str,
        owners: &[u8],
        outputs: Vec<(u8, u128)>,
        remote: Option<(&str, u8, u128, u128)>,
        fee: u128,
    ) -> Result<SignedIntent> {
        let chain = self.chain(region)?;
        let trust = Trust::verify(&self.bootstrap, &public(1), self.pin)?;
        let mut inputs = chain
            .ledger
            .coins
            .iter()
            .filter(|(_, c)| {
                owners.iter().any(|o| public(*o) == c.payment.owner)
                    && c.mature <= chain.height() + 1
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        inputs.sort();
        let intent = Intent {
            currency: self.pin,
            region: chain.region,
            inputs,
            outputs: outputs
                .into_iter()
                .map(|(owner, amount)| Payment {
                    owner: public(owner),
                    amount: Amount(amount),
                })
                .collect(),
            fee: Amount(fee),
            destination: remote.map(|(r, _, _, _)| trust.named(r)).transpose()?,
            remote: remote.map(|(_, o, a, _)| Payment {
                owner: public(o),
                amount: Amount(a),
            }),
            destination_fee: Amount(remote.map(|(_, _, _, fee)| fee).unwrap_or(0)),
            valid_through: 100,
        };
        let mut approvals = owners
            .iter()
            .map(|seed| {
                Ok(Approval {
                    key: public(*seed),
                    signature: signature(*seed, &intent.bytes()?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        approvals.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(SignedIntent { intent, approvals })
    }
    fn reject(&mut self, region: &str, commands: Vec<Command>, label: &str) -> Result<()> {
        let before = self.chain(region)?.ledger.root()?;
        let path = self.root.join("attack.json");
        save(&path, &commands)?;
        let result = self.cli(
            region,
            &[
                "mine".into(),
                "--miner".into(),
                public(10),
                "--commands".into(),
                path.display().to_string(),
            ],
            false,
        )?;
        if self.chain(region)?.ledger.root()? != before {
            return Err("rejection mutated ledger".into());
        }
        self.checks
            .push(json!({"attack":label,"result":result,"unchanged_state":true}));
        Ok(())
    }
}
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("new absolute output directory required")?,
    );
    if args.next().is_some() || !root.is_absolute() || root.exists() {
        return Err("only a NEW absolute fixture directory is accepted".into());
    }
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("rld-regional-ledger-candidate");
    if !binary.is_file() {
        return Err("build all candidate binaries first".into());
    }
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
    currency.signature = signature(1, &currency.bytes()?)?;
    let pin = currency.id()?;
    let admissions = ["earth", "proxima", "andromeda"]
        .into_iter()
        .map(|region| {
            let mut admission = Admission {
                currency: pin,
                region: region.into(),
                rules: "RLD-REGIONAL-FIXTURE-V1".into(),
                value_rules: None,
                validators: seeds(region).into_iter().map(public).collect(),
                signature: String::new(),
            };
            admission.signature = signature(1, &admission.bytes()?)?;
            Ok(admission)
        })
        .collect::<Result<Vec<_>>>()?;
    let bootstrap = Bootstrap {
        currency,
        admissions,
    };
    fs::create_dir(&root).map_err(|e| e.to_string())?;
    save(&root.join("bootstrap.json"), &bootstrap)?;
    let mut c = Campaign {
        root: root.clone(),
        binary,
        bootstrap,
        pin,
        checks: vec![],
        calls: 0,
        lock_heads: BTreeMap::new(),
        validator_seeds: ["earth", "proxima", "andromeda"]
            .into_iter()
            .map(|r| (r.into(), seeds(r)))
            .collect(),
    };
    fs::create_dir(root.join("signers")).map_err(|e| e.to_string())?;
    fs::create_dir(root.join("public-fixture-key-inputs")).map_err(|e| e.to_string())?;
    for region in ["earth", "proxima", "andromeda"] {
        c.cli(
            region,
            &[
                "init".into(),
                "--bootstrap".into(),
                root.join("bootstrap.json").display().to_string(),
                "--region".into(),
                region.into(),
            ],
            true,
        )?;
    }
    for region in ["earth", "proxima", "andromeda"] {
        for seed in seeds(region) {
            c.init_signer(region, seed)?;
        }
    }
    let first_seed = seeds("earth")[0];
    let stale_backup = fs::read(c.signer_dir("earth", first_seed).join("signer.json"))
        .map_err(|e| e.to_string())?;
    for _ in 0..4 {
        c.mine("earth", vec![])?;
    }
    c.certify("earth")?;
    c.stale_signer_drill("earth", first_seed, &stale_backup)?;
    let earth_epoch = c.rotate_earth()?;
    // Two separate source coins, two destinations; an original debit never
    // becomes spendable merely because a receipt or timeout is observed.
    let mut outbound = c.spend(
        "earth",
        &[10],
        vec![(10, 19)],
        Some(("proxima", 11, 80, 2)),
        1,
    )?;
    let original = c.chain("earth")?;
    let mature = original
        .ledger
        .coins
        .iter()
        .filter(|(_, coin)| coin.mature <= 5)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    outbound.intent.inputs = vec![mature[0]];
    outbound.approvals[0].signature = signature(10, &outbound.intent.bytes()?)?;
    let first = outbound.intent.id()?;
    let mut direct = c.spend(
        "earth",
        &[10],
        vec![(10, 49)],
        Some(("andromeda", 12, 50, 2)),
        1,
    )?;
    direct.intent.inputs = vec![mature[1]];
    direct.approvals[0].signature = signature(10, &direct.intent.bytes()?)?;
    let second = direct.intent.id()?;
    c.mine(
        "earth",
        vec![
            Command::Spend(Box::new(outbound)),
            Command::Spend(Box::new(direct)),
        ],
    )?;
    let earth_sid = c.certify("earth")?;
    let earth_root = c.chain("earth")?.ledger.root()?;
    c.carry("earth", "proxima")?;
    c.reject(
        "proxima",
        vec![Command::Import {
            snapshot: earth_sid,
            export: second,
        }],
        "wrong destination",
    )?;
    c.mine(
        "proxima",
        vec![Command::Import {
            snapshot: earth_sid,
            export: first,
        }],
    )?;
    c.reject(
        "proxima",
        vec![Command::Import {
            snapshot: earth_sid,
            export: first,
        }],
        "duplicate import",
    )?;
    let mut premature = c.spend("proxima", &[11], vec![(12, 78)], None, 0)?;
    premature.intent.inputs = c
        .chain("proxima")?
        .ledger
        .coins
        .iter()
        .filter(|(_, coin)| coin.payment.owner == public(11))
        .map(|(id, _)| *id)
        .collect();
    premature.approvals[0].signature = signature(11, &premature.intent.bytes()?)?;
    c.reject(
        "proxima",
        vec![Command::Spend(Box::new(premature))],
        "immature payment",
    )?;
    for _ in 0..2 {
        c.mine("proxima", vec![])?;
    }
    let unfinalized = c.spend("proxima", &[11], vec![], Some(("andromeda", 12, 78, 0)), 0)?;
    c.reject(
        "proxima",
        vec![Command::Spend(Box::new(unfinalized))],
        "mature input lacking local finality",
    )?;
    c.certify("proxima")?;
    let payment = c.spend("proxima", &[11], vec![(12, 30), (11, 47)], None, 1)?;
    c.mine("proxima", vec![Command::Spend(Box::new(payment))])?;
    c.certify("proxima")?;
    let onward = c.spend("proxima", &[12], vec![], Some(("andromeda", 12, 29, 1)), 1)?;
    let onward_id = onward.intent.id()?;
    c.mine("proxima", vec![Command::Spend(Box::new(onward))])?;
    let proxima_sid = c.certify("proxima")?;
    c.carry("proxima", "andromeda")?;
    c.mine(
        "andromeda",
        vec![
            Command::Import {
                snapshot: earth_sid,
                export: second,
            },
            Command::Import {
                snapshot: proxima_sid,
                export: onward_id,
            },
        ],
    )?;
    for _ in 0..2 {
        c.mine("andromeda", vec![])?;
    }
    c.certify("andromeda")?;
    let merged = c.spend("andromeda", &[12], vec![(12, 30), (13, 45)], None, 1)?;
    c.mine("andromeda", vec![Command::Spend(Box::new(merged))])?;
    c.certify("andromeda")?;
    let returning = c.spend(
        "andromeda",
        &[12, 13],
        vec![],
        Some(("earth", 14, 74, 1)),
        1,
    )?;
    let returning_id = returning.intent.id()?;
    let mut forged = returning.clone();
    forged.approvals.pop();
    c.reject(
        "andromeda",
        vec![Command::Spend(Box::new(forged))],
        "missing second owner signature",
    )?;
    c.mine("andromeda", vec![Command::Spend(Box::new(returning))])?;
    let andromeda_sid = c.certify("andromeda")?;
    if c.chain("earth")?.ledger.root()? != earth_root {
        return Err("Earth changed during disconnected regional execution".into());
    }
    c.audit("Earth unused during remote payments and onward value; return pending")?;
    c.carry("andromeda", "proxima")?;
    c.carry("proxima", "earth")?;
    c.mine(
        "earth",
        vec![Command::Import {
            snapshot: andromeda_sid,
            export: returning_id,
        }],
    )?;
    c.reject(
        "earth",
        vec![Command::Import {
            snapshot: andromeda_sid,
            export: returning_id,
        }],
        "cyclic replay at origin",
    )?;
    let final_earth = c.chain("earth")?;
    if !final_earth.ledger.exports.contains_key(&first) || first == returning_id {
        return Err("return reused initial debit".into());
    }
    // Mature the returned asset, then inject authenticated Proxima signer
    // equivocation. Earth-native outputs must remain usable while the returned
    // dependency is quarantined; both retained liabilities and supply survive.
    for _ in 0..2 {
        c.mine("earth", vec![])?;
    }
    let trust = Trust::verify(&c.bootstrap, &public(1), c.pin)?;
    let prox = c.chain("proxima")?;
    let journal: Journal =
        rld_regional_ledger_candidate::history::read_journal(&root.join("proxima"))?;
    let accepted = journal
        .evidence
        .snapshots
        .iter()
        .find(|s| s.statement.id().ok() == prox.finalized)
        .ok_or("missing Proxima fixture checkpoint")?
        .clone();
    let mut fork = Chain::new(prox.region, &trust)?;
    for _ in 0..prox.height() + 1 {
        let mut block = fork.template(vec![], public(14), &trust, &VerifiedEvidence::default())?;
        mine(&mut block)?;
        fork.accept(block, &trust, &VerifiedEvidence::default())?;
    }
    let statement = fork.statement(&trust)?;
    let approvals = seeds("proxima")
        .into_iter()
        .map(|seed| {
            Ok(Approval {
                key: public(seed),
                signature: signature(seed, &statement.bytes()?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let competing = Snapshot {
        base: None,
        bft: None,
        statement,
        approvals,
        blocks: fork.blocks,
        epochs: vec![],
    };
    let proof =
        rld_regional_ledger_candidate::conflict::Conflict::from_snapshots(&accepted, &competing)?;
    proof.verify(&trust)?;
    let mut forged_proof = proof;
    forged_proof.right.approvals[0].signature = "00".into();
    let path = root.join("incident.json");
    save(&path, &forged_proof)?;
    let before = c.chain("earth")?.ledger.root()?;
    c.cli(
        "earth",
        &[
            "incident".into(),
            "--file".into(),
            path.display().to_string(),
        ],
        false,
    )?;
    save(
        &path,
        &Evidence {
            snapshots: vec![competing],
        },
    )?;
    c.cli(
        "earth",
        &[
            "evidence".into(),
            "--file".into(),
            path.display().to_string(),
        ],
        false,
    )?;
    let observed: Vec<rld_regional_ledger_candidate::conflict::Conflict> =
        serde_json::from_value(c.cli("earth", &["incidents".into()], true)?)
            .map_err(|e| e.to_string())?;
    if observed.len() != 1 || c.chain("earth")?.ledger.root()? != before {
        return Err("conflict observation altered accepted value".into());
    }
    let incident_id = observed[0].id()?;
    save(&path, &observed[0])?;
    for region in ["proxima", "andromeda"] {
        c.cli(
            region,
            &[
                "incident".into(),
                "--file".into(),
                path.display().to_string(),
            ],
            true,
        )?;
        c.audit(&format!(
            "signed incident propagated to {region}; no refund"
        ))?;
    }
    let affected_payment = c.spend("earth", &[14], vec![(15, 72)], None, 1)?;
    c.reject(
        "earth",
        vec![Command::Spend(Box::new(affected_payment))],
        "mature returned asset depends on faulted Proxima",
    )?;
    c.reject(
        "proxima",
        vec![],
        "faulted local finality prevents new blocks",
    )?;
    c.cli("proxima", &["statement".into()], false)?;
    let state = c.cli("earth", &["status".into()], true)?;
    if state["exposure"]["retained_coin_amount"] != json!("74") {
        return Err("expected returned exposure of 74 fixture units".into());
    }
    let quarantined =
        serde_json::from_value::<Vec<Hash>>(state["exposure"]["quarantined_coins"].clone())
            .map_err(|e| e.to_string())?;
    let local = c.chain("earth")?;
    let safe = local
        .ledger
        .coins
        .iter()
        .find(|(id, coin)| {
            !quarantined.contains(id)
                && coin.payment.owner == public(10)
                && coin.payment.amount == Amount(100)
        })
        .ok_or("safe origin output missing")?;
    let intent = Intent {
        currency: c.pin,
        region: local.region,
        inputs: vec![*safe.0],
        outputs: vec![Payment {
            owner: public(15),
            amount: Amount(99),
        }],
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 100,
    };
    let signature = signature(10, &intent.bytes()?)?;
    c.mine(
        "earth",
        vec![Command::Spend(Box::new(SignedIntent {
            intent,
            approvals: vec![Approval {
                key: public(10),
                signature,
            }],
        }))],
    )?;
    c.mine("andromeda", vec![])?;
    // Corrupt the retained file as a partial-write recovery drill. Recovery
    // restores the exact indexed proof and preserves its quarantine.
    let retained = root
        .join("earth/incidents")
        .join(format!("{}.json", incident_id.to_hex()));
    fs::write(&retained, b"half-written").map_err(|e| e.to_string())?;
    c.cli("earth", &["status".into()], false)?;
    c.cli(
        "earth",
        &[
            "recover-incident".into(),
            "--file".into(),
            path.display().to_string(),
        ],
        true,
    )?;
    c.audit("damaged incident repaired; same quarantine and conservation")?;
    for region in ["earth", "proxima", "andromeda"] {
        let status = c.cli(region, &["status".into()], true)?;
        if status["incident_ids"] != json!([incident_id]) {
            return Err("incident identity did not survive propagation and restart".into());
        }
    }
    let report = json!({"format":"RLD-REGIONAL-NATIVE-FIXTURE-CAMPAIGN-V1","result":"PASS_BOUNDED_NATIVE_CLI_CAMPAIGN","currency":pin,"implementation":implementation()?,"native_cli_process_invocations":c.calls,"all_normal_checkpoints_use_persisted_native_signer_agents":true,"earth_validator_epoch":earth_epoch,"joint_epoch_handoff_and_offline_relay_verified":true,"stale_signer_backup_refused_with_surviving_external_pin":true,"regions":3,"authenticated_conflict_id":incident_id,"conflict_propagation_and_dependency_quarantine_verified":true,"damaged_incident_recovered_without_unfreezing":true,"earth_retained_quarantined_return_amount":"74","region_validator_keys_distinct":true,"owners":6,"checks":c.checks,"original_export":first,"direct_earth_to_andromeda_export":second,"onward_export":onward_id,"new_return_export":returning_id,"mainnet_authorized":false,"physical_route_verified":false,"independent_operators":false,"logical_years_or_physical_aging_tested":false,"live_rld":false,"source_http_used":false,"consensus_scope":"append-only mined histories, durable signer locks with caller-retained heads and joint unanimous epoch handoff; public fixture keys, no BFT view change or authorized release of quarantined exposures","limits":{"blocks_per_region":MAX_BLOCKS,"snapshots":MAX_SNAPSHOTS,"journal_bytes":MAX_BYTES},"unimplemented":["native mesh automation and real contact adapter","fork selection and independent regional BFT qualification","consensus conflict resolution and independent recovery authority","channels and reservations","BFT validator reconfiguration and cryptographic horizon","external rollback root and independent archives"]});
    save(&root.join("report.json"), &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("fixture campaign failed: {error}");
        std::process::exit(1);
    }
}
