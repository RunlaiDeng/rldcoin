//! Native no-value node. Control JSON uses bounded local stdin/stdout, never a
//! public signing socket. Secret material is never copied into responses.
use rld_survivor_node::{
    kernel::{Hash, MiningJob, Result},
    keyfile,
    operating_policy::OperatingPolicy,
    store::{Limits, Store},
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Read, Write},
    path::Path,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "CLOCK_WAIT".into())
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().ok_or_else(|| format!("INVALID_ENCODING {k}"))
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> {
    let s = field(v, k)?;
    if s.bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("INVALID_ENCODING lowercase hex".into());
    }
    hex::decode(s).map_err(|_| "INVALID_ENCODING hex".into())
}
fn hash(v: &Value, k: &str) -> Result<Hash> {
    bytes(v, k)?
        .try_into()
        .map_err(|_| "INVALID_ENCODING hash".into())
}
fn integer(v: &Value, k: &str) -> Result<u128> {
    let s = field(v, k)?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err("INVALID_ENCODING integer".into());
    }
    s.parse().map_err(|_| "INVALID_ENCODING integer".into())
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let f = std::fs::File::open(path).map_err(|_| "MISSING_HISTORY local file")?;
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|_| "RESOURCE_WAIT file read")?;
    if b.len() as u64 > max {
        return Err("INVALID_ENCODING file size".into());
    }
    Ok(b)
}
fn write_private(path: &Path, raw: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|_| "RESOURCE_WAIT fresh file required")?;
    f.write_all(raw)
        .and_then(|_| f.sync_all())
        .map_err(|_| "RESOURCE_WAIT key persistence")?;
    std::fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|d| d.sync_all())
    .map_err(|_| "RESOURCE_WAIT directory persistence".into())
}
fn operation() -> Result<Hash> {
    let mut id = [0; 32];
    getrandom::getrandom(&mut id).map_err(|_| "RESOURCE_WAIT entropy")?;
    if id == [0; 32] {
        return Err("RESOURCE_WAIT entropy".into());
    }
    Ok(id)
}
fn response(s: &Store, result: Value, clock: Option<u64>, diagnostic: Option<&str>) -> Value {
    let diagnostic = diagnostic.or_else(|| {
        (!s.storage_ready()).then_some("RESOURCE_WAIT storage verification/restart required")
    });
    json!({"profile":"RLD-SURVIVOR-1","chain_id":hex::encode(s.ledger().chain_id()),"selected_tip":hex::encode(s.ledger().tip().id()),"revision":s.revision().to_string(),"observed_at":clock.map(|x|x.to_string()),"clock_state":if clock.is_some(){"OBSERVED"}else{"CLOCK_WAIT"},"storage_state":if s.storage_ready(){"READY"}else{"RESTART_REQUIRED"},"confidence":"CONDITIONAL","diagnostic":diagnostic,"error_code":diagnostic.map(error_code),"result":result})
}
fn error_code(e: &str) -> &'static str {
    for category in [
        "INVALID_ENCODING",
        "WRONG_CHAIN",
        "UNSUPPORTED_VERSION",
        "INVALID_CRYPTO",
        "INVALID_CONSENSUS",
        "OPERATION_ID_CONFLICT",
        "MISSING_HISTORY",
        "CONFLICT",
        "IMMATURE",
        "EXPIRED",
        "CLOCK_WAIT",
        "RESOURCE_WAIT",
        "REORG_WAIT",
        "FRESHNESS_UNKNOWN",
        "RESYNC_REQUIRED",
    ] {
        if e.starts_with(category) {
            return category;
        }
    }
    if e.contains("WAITING_FOR_HISTORY") || e.contains("WAITING_FOR_INPUT") {
        "MISSING_HISTORY"
    } else if e.contains("WAITING_FOR_MATURITY") {
        "IMMATURE"
    } else if e.contains("UNSUPPORTED") {
        "UNSUPPORTED_VERSION"
    } else if e.contains("signature") || e.contains("public key") {
        "INVALID_CRYPTO"
    } else if e.contains("chain") {
        "WRONG_CHAIN"
    } else {
        "INVALID_CONSENSUS"
    }
}
fn command(
    s: &mut Store,
    v: &Value,
    miner: &mut Option<Hash>,
    network: &mut Option<rld_survivor_node::network::Network>,
    network_error: &Option<String>,
    clock: Option<u64>,
) -> Result<Value> {
    let time = || clock.ok_or_else(|| "CLOCK_WAIT".to_string());
    match field(v, "method")? {
        "node_status" => Ok(
            json!({"height":s.ledger().tip().height().to_string(),"issued":s.ledger().issued().to_string(),"state_root":hex::encode(s.ledger().tip().root()),"freshness":s.freshness()?,"mining_enabled":miner.is_some(),"mining":miner.is_some()&&clock.is_some_and(|t|s.clock(t).is_ok()),"relay":network.as_ref().map(|n|n.status()),"transport_error":network_error,"mainnet":false}),
        ),
        "get_object" => {
            let kind = field(v, "kind")?;
            let id = hash(v, "id")?;
            let raw = match kind {
                "1" if id == s.ledger().chain_id() => s.genesis_bytes().to_vec(),
                "2" => s.get_transaction(id)?,
                "3" => s.get_block(id)?,
                _ => return Err("UNSUPPORTED_VERSION object kind".into()),
            };
            Ok(json!({"bytes":hex::encode(raw)}))
        }
        "capsule_export" => {
            let intent = bytes(v, "transaction_hex")?;
            let id = rld_survivor_node::capsule::export(
                s,
                &intent,
                Path::new(field(v, "capsule_file")?),
            )?;
            Ok(
                json!({"capsule_id":hex::encode(id),"transaction_hex":hex::encode(intent),"local_ledger_acceptance":false}),
            )
        }
        "capsule_refresh" => {
            let id = rld_survivor_node::capsule::refresh(
                s,
                Path::new(field(v, "prior_capsule_file")?),
                Path::new(field(v, "capsule_file")?),
            )?;
            Ok(
                json!({"capsule_id":hex::encode(id),"unchanged_intent":true,"local_ledger_acceptance":false}),
            )
        }
        "capsule_verify" => {
            let expected = v
                .get("expected_transaction_hex")
                .map(|_| bytes(v, "expected_transaction_hex"))
                .transpose()?;
            let verified = rld_survivor_node::capsule::verify(
                Path::new(field(v, "capsule_file")?),
                s.genesis_bytes(),
                s.ledger().chain_id(),
                s.resource_limits(),
                expected.as_deref(),
            )?;
            Ok(verified.observation(clock))
        }
        "capsule_import" => {
            let expected = v
                .get("expected_transaction_hex")
                .map(|_| bytes(v, "expected_transaction_hex"))
                .transpose()?;
            rld_survivor_node::capsule::import(
                s,
                Path::new(field(v, "capsule_file")?),
                expected.as_deref(),
                time()?,
            )
        }
        "accept_block" => {
            let o = s.accept(hash(v, "operation_id")?, &bytes(v, "block_hex")?, time()?)?;
            Ok(
                json!({"result_tip":hex::encode(o.tip),"result_revision":o.revision.to_string(),"selected":o.selected}),
            )
        }
        "accept_history" => {
            let items = v["blocks"]
                .as_array()
                .ok_or("INVALID_ENCODING history blocks")?;
            if !(1..=32).contains(&items.len()) {
                return Err("INVALID_ENCODING history count".into());
            }
            let blocks = items
                .iter()
                .map(|x| bytes(&json!({"raw":x}), "raw"))
                .collect::<Result<Vec<_>>>()?;
            let o = s.accept_history(hash(v, "operation_id")?, &blocks, time()?)?;
            Ok(
                json!({"result_tip":hex::encode(o.tip),"result_revision":o.revision.to_string(),"selected":o.selected}),
            )
        }
        "submit_transaction" => {
            let id = s.submit_transaction(
                hash(v, "operation_id")?,
                &bytes(v, "transaction_hex")?,
                time()?,
            )?;
            if let Some(n) = network.as_mut() {
                n.queue_transaction(&bytes(v, "transaction_hex")?)?;
            }
            Ok(json!({"transaction_id":hex::encode(id),"submission":"RETAINED","ledger":null}))
        }
        "review_transfer" => {
            let digest = s.review_transfer(
                hash(v, "operation_id")?,
                &bytes(v, "unsigned_hex")?,
                time()?,
            )?;
            Ok(json!({"review_digest":hex::encode(digest),"local_intent":"REVIEWED"}))
        }
        "propose_transfer" => {
            let owner = hash(v, "owner")?;
            let inputs = v["inputs"].as_array().ok_or("INVALID_ENCODING inputs")?;
            let outputs = v["outputs"].as_array().ok_or("INVALID_ENCODING outputs")?;
            if !(1..=32).contains(&inputs.len()) || !(1..=8).contains(&outputs.len()) {
                return Err("INVALID_ENCODING transfer count".into());
            }
            let mut ids = Vec::new();
            for id in inputs {
                let b = bytes(&json!({"id":id}), "id")?;
                if b.len() != 34 {
                    return Err("INVALID_ENCODING outpoint".into());
                }
                ids.push(b);
            }
            ids.sort();
            let mut u = 1u16.to_be_bytes().to_vec();
            u.extend(s.ledger().chain_id());
            u.extend(owner);
            u.extend((ids.len() as u16).to_be_bytes());
            for id in &ids {
                u.extend(id);
            }
            u.extend((outputs.len() as u16).to_be_bytes());
            for output in outputs {
                u.extend(hash(output, "owner")?);
                u.extend(integer(output, "amount")?.to_be_bytes());
            }
            let fee = integer(v, "fee")?;
            let expiry = if v.get("expiry").is_some() {
                integer(v, "expiry")?
            } else {
                u128::MAX
            };
            u.extend(fee.to_be_bytes());
            u.extend(expiry.to_be_bytes());
            let digest = s.review_transfer(hash(v, "operation_id")?, &u, time()?)?;
            Ok(
                json!({"review_digest":hex::encode(digest),"unsigned_hex":hex::encode(u),"local_intent":"REVIEWED","review":{"owner":hex::encode(owner),"inputs":ids.iter().map(hex::encode).collect::<Vec<_>>(),"outputs":outputs,"fee":fee.to_string(),"expiry":expiry.to_string()}}),
            )
        }
        "sign_review" => {
            let p = Zeroizing::new(field(v, "password")?.as_bytes().to_vec());
            let raw = read(Path::new(field(v, "key_file")?), 187)?;
            let key = keyfile::decrypt(&raw, s.ledger().chain_id(), &p)?;
            let x = s.sign_review(
                hash(v, "operation_id")?,
                hash(v, "review_digest")?,
                &key,
                time()?,
            )?;
            Ok(json!({"transaction_hex":hex::encode(x),"local_intent":"SIGNED"}))
        }
        "operation_status" => {
            let id = hash(v, "operation_id")?;
            if let Some(mut observation) = s.payment_operation(id)? {
                if let Some(raw) = observation["transaction_hex"].as_str() {
                    let raw =
                        hex::decode(raw).map_err(|_| "INVALID_ENCODING retained transaction")?;
                    observation["transport"] = if let Some(n) = network.as_ref() {
                        n.transaction_observation(&raw)?
                    } else {
                        json!({"state":"NOT_QUEUED","diagnostic":network_error})
                    };
                }
                Ok(observation)
            } else if let Some(o) = s.operation(id)? {
                Ok(
                    json!({"result_tip":hex::encode(o.tip),"result_revision":o.revision.to_string(),"selected":o.selected}),
                )
            } else {
                Ok(s.pending_operation(id)?.unwrap_or(json!({"result":null})))
            }
        }
        "wallet_state" => {
            let owner = hash(v, "owner")?;
            let b = s.wallet_state(owner)?;
            let outputs: Vec<_> = s.wallet_outputs(owner)?.into_iter().map(|(id,c,reserved)|json!({"outpoint":hex::encode(id),"amount":c.amount.to_string(),"maturity_height":c.maturity.to_string(),"eligible_next_height": c.maturity<=s.ledger().tip().height()+1,"reserved":reserved})).collect();
            Ok(
                json!({"unspent":b.unspent.to_string(),"immature":b.immature.to_string(),"mature":b.mature.to_string(),"reserved":b.reserved.to_string(),"available":b.available.to_string(),"outputs":outputs}),
            )
        }
        "waive_reservation" => {
            s.waive_reservation(
                hash(v, "operation_id")?,
                v["acknowledge_conflicting_branch"].as_bool() == Some(true),
            )?;
            Ok(json!({"local_intent":"WITHDRAWN","signature_revoked":false}))
        }
        "changes_since" => s.changes_since(integer(v, "revision")?),
        "set_mining" => {
            let enabled = v["enabled"].as_bool().ok_or("INVALID_ENCODING enabled")?;
            if enabled {
                let time = time()?;
                s.clock(time)?;
                let k = hash(v, "miner")?;
                let timestamp = time.max(
                    s.ledger()
                        .tip()
                        .timestamp()
                        .checked_add(1)
                        .ok_or("CLOCK_WAIT timestamp exhausted")?,
                );
                s.ledger().mining_job(k, vec![], timestamp, time)?;
                *miner = Some(k)
            } else {
                *miner = None
            }
            Ok(json!({"mining":enabled}))
        }
        "create_key" => {
            let p = Zeroizing::new(field(v, "password")?.as_bytes().to_vec());
            let key = keyfile::generate()?;
            let raw = keyfile::encrypt(&key, s.ledger().chain_id(), &p)?;
            write_private(Path::new(field(v, "key_file")?), &raw)?;
            Ok(
                json!({"owner":hex::encode(key.verifying_key().to_bytes()),"backup_scope":"KEY_ONLY"}),
            )
        }
        "state_head" => {
            let n = network
                .as_ref()
                .ok_or("RESOURCE_WAIT contact state unavailable")?;
            Ok(
                json!({"state_head":hex::encode(rld_survivor_node::backup::state_head(s,n)?),"intent_head":hex::encode(s.intent_head()?),"freshness":s.freshness()?}),
            )
        }
        "offline_export" => {
            let n = network
                .as_mut()
                .ok_or("RESOURCE_WAIT contact state unavailable")?;
            Ok(
                json!({"frames":n.offline_export(hash(v,"peer_key")?)?.iter().map(hex::encode).collect::<Vec<_>>(),"receipt_required":true}),
            )
        }
        "offline_import" => {
            let n = network
                .as_mut()
                .ok_or("RESOURCE_WAIT contact state unavailable")?;
            let raw = read(Path::new(field(v, "frame_file")?), 1048588)?;
            Ok(
                json!({"receipt":n.offline_import(hash(v,"peer_key")?,&raw)?.map(hex::encode),"ledger_acceptance":false}),
            )
        }
        "withdraw_transport" => {
            let n = network
                .as_mut()
                .ok_or("RESOURCE_WAIT contact state unavailable")?;
            n.withdraw_transport(
                hash(v, "packet_id")?,
                v["acknowledge_undelivered_loss"].as_bool() == Some(true),
            )?;
            Ok(
                json!({"transport_obligation":"OWNER_WITHDRAWN","delivery_guarantee_abandoned":true,"signature_revoked":false}),
            )
        }
        "discovery_candidates" => network
            .as_ref()
            .ok_or("RESOURCE_WAIT contact state unavailable")?
            .discovered_candidates(),
        "create_backup" => {
            let n = network
                .as_ref()
                .ok_or("RESOURCE_WAIT contact state unavailable")?;
            let p = Zeroizing::new(field(v, "password")?.as_bytes().to_vec());
            let paths = v["wallet_key_files"]
                .as_array()
                .ok_or("INVALID_ENCODING wallet key inventory")?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(std::path::PathBuf::from)
                        .ok_or_else(|| "INVALID_ENCODING wallet key path".to_string())
                })
                .collect::<Result<Vec<_>>>()?;
            let head = rld_survivor_node::backup::create(
                s,
                n,
                Path::new(field(v, "destination")?),
                &p,
                &paths,
            )?;
            Ok(
                json!({"state_head":hex::encode(head),"scope":"WHOLE_NODE_WITH_LISTED_ENCRYPTED_KEYS","independent_freshness":false}),
            )
        }
        "acknowledge_restore_risk" => {
            s.acknowledge_restore_risk(
                hash(v, "intent_head")?,
                v["acknowledge_conflicting_signatures"].as_bool() == Some(true),
            )?;
            Ok(json!({"freshness":s.freshness()?,"independent_freshness":false}))
        }
        _ => Err("UNSUPPORTED_VERSION method".into()),
    }
}
fn run() -> Result<()> {
    let mut a: Vec<_> = std::env::args().collect();
    let policy_file = if a.len() >= 3 && a[a.len() - 2] == "--operating-policy" {
        let path = a.pop().unwrap();
        a.pop();
        Some(path)
    } else {
        None
    };
    if a.iter().any(|v| v == "--operating-policy") {
        return Err("INVALID_ENCODING operating policy argument position".into());
    }
    if a.len() == 3 && a[1] == "new-test-genesis" {
        if policy_file.is_some() {
            return Err("INVALID_ENCODING genesis does not accept operating policy".into());
        }
        let mut g = b"RLDSGEN1".to_vec();
        g.extend(1u16.to_be_bytes());
        g.extend(1u16.to_be_bytes());
        g.push(0);
        g.extend(operation()?);
        g.extend(now()?.to_be_bytes());
        g.push(0);
        g.extend([255; 31]);
        let pin = rld_survivor_node::kernel::genesis_id(&g);
        rld_survivor_node::kernel::Ledger::from_genesis(&g, pin, Limits::default().coins)?;
        write_private(Path::new(&a[2]), &g)?;
        println!(
            "{}",
            json!({"profile":"RLD-SURVIVOR-1","chain_id":hex::encode(pin),"genesis_file":a[2],"initial_allocation":"0","network_kind":"NO_VALUE_ONLY"})
        );
        return Ok(());
    }
    if !(5..=6).contains(&a.len()) || !matches!(a[1].as_str(), "serve" | "restore") {
        return Err("Usage: rld-survivor-node serve PRIVATE_DIRECTORY GENESIS_FILE PINNED_CHAIN_ID [CONTACT_CONFIG] [--operating-policy LOCAL_FILE]; bounded local JSON lines on stdin; test networks only".into());
    }
    let g = read(Path::new(&a[3]), 85)?;
    let pin: Hash = hex::decode(&a[4])
        .map_err(|_| "INVALID_ENCODING pin")?
        .try_into()
        .map_err(|_| "INVALID_ENCODING pin")?;
    let policy = if let Some(path) = &policy_file {
        if !std::fs::symlink_metadata(path)
            .map_err(|_| "MISSING_HISTORY operating policy")?
            .file_type()
            .is_file()
        {
            return Err("INVALID_ENCODING operating policy regular file".into());
        }
        OperatingPolicy::decode(&read(Path::new(path), 16384)?, pin)?
    } else {
        OperatingPolicy::default()
    };
    if a[1] == "restore" {
        if a.len() != 6 {
            return Err("INVALID_ENCODING restore requires fresh target, genesis, pin, backup source; password on native stdin".into());
        }
        let mut input = Zeroizing::new(Vec::new());
        io::stdin()
            .lock()
            .take(65537)
            .read_until(b'\n', &mut input)
            .map_err(|_| "RESOURCE_WAIT restore input")?;
        if input.len() > 65536 {
            return Err("INVALID_ENCODING restore input bound".into());
        }
        let mut v: Value =
            serde_json::from_slice(&input).map_err(|_| "INVALID_ENCODING restore request")?;
        let password = Zeroizing::new(field(&v, "password")?.as_bytes().to_vec());
        if let Some(Value::String(p)) = v.get_mut("password") {
            use zeroize::Zeroize;
            p.zeroize();
        }
        let latest = if v["latest_state_head"].is_null() {
            None
        } else {
            Some(hash(&v, "latest_state_head")?)
        };
        let head = rld_survivor_node::backup::restore_with_policy(
            Path::new(&a[5]),
            Path::new(&a[2]),
            &g,
            pin,
            &password,
            latest,
            policy,
        )?;
        println!(
            "{}",
            json!({"profile":"RLD-SURVIVOR-1","chain_id":hex::encode(pin),"state_head":hex::encode(head),"freshness":if latest.is_some(){"MATCHES_PROVIDED_HEAD"}else{"FRESHNESS_UNKNOWN"},"independent_freshness":false})
        );
        return Ok(());
    }
    let mut s = Store::open(Path::new(&a[2]), &g, pin, policy.ledger())?;
    let retained_config = Path::new(&a[2]).join("contact/config.json");
    let config = if let Some(p) = a.get(5) {
        Some(read(Path::new(p), 65536)?)
    } else if retained_config.exists() {
        Some(read(&retained_config, 65536)?)
    } else {
        None
    };
    let (mut network, mut network_error) =
        match rld_survivor_node::network::Network::open_with_budget(
            &Path::new(&a[2]).join("contact"),
            pin,
            config.as_deref(),
            policy.carriage(),
        ) {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(e)),
        };
    let (tx, rx) = mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            let mut b = Zeroizing::new(Vec::new());
            let n = (&mut stdin)
                .take(2 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut b);
            match n {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if b.len() > 2 * 1024 * 1024 || !b.ends_with(b"\n") {
                        let _ = tx.send(Err("INVALID_ENCODING request bound".to_string()));
                        break;
                    }
                    let parsed = serde_json::from_slice::<Value>(&b)
                        .map_err(|_| "INVALID_ENCODING JSON".to_string());
                    if tx.send(parsed).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut miner = None;
    let mut job: Option<(Hash, u64, Hash, MiningJob)> = None;
    let mut hash_attempts = Some(0u128);
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(request) => {
                let clock = now().ok();
                let observed_clock = clock.filter(|t| match s.clock(*t) {
                    Ok(()) => true,
                    Err(e) => !e.starts_with("CLOCK_WAIT"),
                });
                let r = match request {
                    Ok(mut v) => {
                        let status = v["method"] == "node_status";
                        let r =
                            command(&mut s, &v, &mut miner, &mut network, &network_error, clock)
                                .map(|mut result| {
                                    if status {
                                        result["operating_policy"] = policy.status(pin);
                                    result["mining_work_observation"] = json!({"scope":"CURRENT_PROCESS_HEADER_HASH_CALLS","calls":hash_attempts.map(|n| n.to_string()),"count_exact":hash_attempts.is_some(),"distinctness":"PER_JOB_NONCE_ONLY","serialized":false});
                                        result["operating_policy_source"] =
                                            json!(if policy_file.is_some() {
                                                "EXPLICIT_LOCAL_FILE"
                                            } else {
                                                "DEFAULT"
                                            });
                                    }
                                    result
                                });
                        if let Some(Value::String(p)) = v.get_mut("password") {
                            use zeroize::Zeroize;
                            p.zeroize()
                        }
                        r
                    }
                    Err(e) => Err(e),
                };
                let out = match r {
                    Ok(v) => response(&s, v, observed_clock, None),
                    Err(e) => response(&s, Value::Null, observed_clock, Some(&e)),
                };
                println!("{out}");
                io::stdout().flush().map_err(|_| "RESOURCE_WAIT output")?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if let (Some(n), Ok(t)) = (network.as_mut(), now()) {
            if let Err(e) = n.tick(&mut s, t) {
                network_error = Some(e);
            }
        }
        if let Some(k) = miner {
            let t = match now() {
                Ok(t) => t,
                Err(e) => {
                    println!("{}", response(&s, Value::Null, None, Some(&e)));
                    job = None;
                    continue;
                }
            };
            if let Err(e) = s.clock(t) {
                println!("{}", response(&s, Value::Null, None, Some(&e)));
                continue;
            }
            let timestamp = t.max(
                s.ledger()
                    .tip()
                    .timestamp()
                    .checked_add(1)
                    .ok_or("CLOCK_WAIT")?,
            );
            let tip = s.ledger().tip().id();
            if job
                .as_ref()
                .is_none_or(|(id, time, owner, _)| *id != tip || *time != timestamp || *owner != k)
            {
                match s
                    .ledger()
                    .mining_job(k, s.template_transactions()?, timestamp, t)
                {
                    Ok(j) => job = Some((tip, timestamp, k, j)),
                    Err(e) => {
                        println!("{}", response(&s, Value::Null, Some(t), Some(&e)));
                        continue;
                    }
                }
            }
            let (raw, tried) = job.as_mut().map_or((None, 0), |(_, _, _, j)| {
                j.attempt_counted(policy.mining_trials())
            });
            // Optional process telemetry cannot halt mining or grant work/value.
            // An exhausted counter becomes explicitly unknown, never zero.
            hash_attempts = hash_attempts.and_then(|n| n.checked_add(u128::from(tried)));
            if let Some(raw) = raw {
                let old = s.revision();
                match s.accept(operation()?, &raw, t) {
                    Ok(_) => println!(
                        "{}",
                        response(
                            &s,
                            json!({"event":"SELECTED_CHANGE","previous_revision":old.to_string()}),
                            Some(t),
                            None
                        )
                    ),
                    Err(e) => println!("{}", response(&s, Value::Null, Some(t), Some(&e))),
                }
                job = None;
            }
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn store() -> Store {
        let mut g = b"RLDSGEN1".to_vec();
        g.extend(1u16.to_be_bytes());
        g.extend(1u16.to_be_bytes());
        g.push(0);
        g.extend([77; 32]);
        g.extend(1_000_000u64.to_be_bytes());
        g.push(0);
        g.extend([255; 31]);
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-clock-status-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Store::open(
            &root,
            &g,
            rld_survivor_node::kernel::genesis_id(&g),
            Limits::default(),
        )
        .unwrap()
    }
    fn reward_key() -> Hash {
        // Deliberately public NO-VALUE fixture owner, never production custody.
        ed25519_dalek::SigningKey::from_bytes(&[11; 32])
            .verifying_key()
            .to_bytes()
    }
    #[test]
    fn unknown_clock_allows_observation_and_disabling_but_not_enabling_mining() {
        let mut s = store();
        let mut miner = Some(reward_key());
        let mut network = None;
        let status = command(
            &mut s,
            &json!({"method":"node_status"}),
            &mut miner,
            &mut network,
            &None,
            None,
        )
        .unwrap();
        assert_eq!(status["mining_enabled"], true);
        assert_eq!(status["mining"], false);
        let out = response(&s, status, None, None);
        assert!(out["observed_at"].is_null());
        assert_eq!(out["clock_state"], "CLOCK_WAIT");
        assert_eq!(out["storage_state"], "READY");
        command(
            &mut s,
            &json!({"method":"set_mining","enabled":false}),
            &mut miner,
            &mut network,
            &None,
            None,
        )
        .unwrap();
        assert!(miner.is_none());
        let request =
            json!({"method":"set_mining","enabled":true,"miner":hex::encode(reward_key())});
        assert_eq!(
            command(&mut s, &request, &mut miner, &mut network, &None, None).unwrap_err(),
            "CLOCK_WAIT"
        );
        assert!(miner.is_none());
        assert_eq!(s.revision(), 0);
    }
    #[test]
    fn detected_storage_fault_preserves_clock_and_reports_paused_mining() {
        let mut s = store();
        let time = 1_000_600;
        let mut job = s
            .ledger()
            .mining_job(reward_key(), vec![], time, time)
            .unwrap();
        let mut raw = job.attempt(1_000_000).unwrap();
        s.accept([1; 32], &raw, time).unwrap();
        let tip = s.ledger().tip().clone();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        let db = rusqlite::Connection::open(s.root().join("ledger.sqlite3")).unwrap();
        db.execute("UPDATE blocks SET raw=?1", [raw]).unwrap();
        drop(db);
        assert!(s.get_block(tip.id()).is_err());
        assert!(!s.storage_ready());
        let mut miner = Some(reward_key());
        let mut network = None;
        let status = command(
            &mut s,
            &json!({"method":"node_status"}),
            &mut miner,
            &mut network,
            &None,
            Some(time),
        )
        .unwrap();
        assert_eq!(status["mining_enabled"], true);
        assert_eq!(status["mining"], false);
        let out = response(&s, status, Some(time), None);
        assert_eq!(out["clock_state"], "OBSERVED");
        assert_eq!(out["storage_state"], "RESTART_REQUIRED");
        assert_eq!(out["error_code"], "RESOURCE_WAIT");
        assert!(s.clock(time - 1).unwrap_err().starts_with("CLOCK_WAIT"));
        command(
            &mut s,
            &json!({"method":"set_mining","enabled":false}),
            &mut miner,
            &mut network,
            &None,
            Some(time),
        )
        .unwrap();
        assert!(miner.is_none());
        assert_eq!(s.ledger().tip(), &tip);
    }
    #[test]
    fn submission_acknowledges_retention_without_inventing_a_ledger_observation() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let genesis = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-submission-status-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut s = Store::open(
            &root,
            &genesis,
            rld_survivor_node::kernel::genesis_id(&genesis),
            Limits::default(),
        )
        .unwrap();
        let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..101]
            .iter()
            .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
            .collect();
        for (i, group) in blocks.chunks(32).enumerate() {
            s.accept_history([i as u8 + 1; 32], group, 2_000_000_000)
                .unwrap();
        }
        let tip = s.ledger().tip().clone();
        let revision = s.revision();
        let mut miner = None;
        let mut network = None;
        let id = hex::encode([66; 32]);
        let submitted = command(&mut s,&json!({"method":"submit_transaction","operation_id":id,"transaction_hex":v["payment"]["transaction_hex"]}),&mut miner,&mut network,&None,Some(2_000_000_000)).unwrap();
        assert_eq!(submitted["submission"], "RETAINED");
        assert!(submitted["ledger"].is_null());
        let observed = command(
            &mut s,
            &json!({"method":"operation_status","operation_id":id}),
            &mut miner,
            &mut network,
            &None,
            Some(2_000_000_000),
        )
        .unwrap();
        assert_eq!(observed["ledger"], "INCLUDED");
        assert_eq!(s.ledger().tip(), &tip);
        assert_eq!(s.revision(), revision);
    }
}
