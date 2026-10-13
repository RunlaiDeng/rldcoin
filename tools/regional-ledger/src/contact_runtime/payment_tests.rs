//! Same-host no-value integration: four separate ledgers and two real wallet callers.
use super::*;
use crate::{
    bft, bft_client,
    tests::{public, signature},
    wallet, wallet_app, wallet_client,
};
use std::sync::mpsc::{self, Receiver, Sender};

// Fix recipient replicas before creating the fixture; never select the fastest
// replica after observing results. All four replicas still must finish and replay.
const FIRST_RECIPIENT: usize = 0;
const SECOND_RECIPIENT: usize = 2;

struct Observation {
    height: u64,
    head: Hash,
    coins: Vec<(Hash, String, crate::Amount, bool)>,
    finalized: bool,
    native_verified_at: f64,
}
struct Sample {
    intent: Hash,
    input: Hash,
    submitted: f64,
    queued: f64,
}
struct Stopped {
    head: Hash,
    wallet: Option<wallet_client::State>,
}
enum Job {
    Observe(Sender<Result<Observation>>),
    Availability {
        paused: bool,
        reply: Sender<Result<Observation>>,
    },
    Pay {
        recipient: String,
        input: Option<Hash>,
        reply: Sender<Result<Sample>>,
    },
}
struct Worker {
    sender: Sender<Job>,
    thread: JoinHandle<Result<Stopped>>,
}
struct Actor {
    options: Options,
    transport: Value,
    runtime: Option<super::super::bft::Runtime>,
    wallet: Option<wallet_app::Options>,
    receiver: Receiver<Job>,
}
fn observe(options: &Options) -> Result<Observation> {
    let node = Store::open_inspection(&options.ledger, &options.authority, options.currency)?;
    let mut coins = Vec::new();
    for seed in [10, 11, 14] {
        for coin in wallet::view(&node, &public(seed))?.coins {
            coins.push((
                coin.id,
                public(seed),
                coin.amount,
                coin.spendable_now && !coin.quarantined,
            ));
        }
    }
    Ok(Observation {
        height: node.chain.height(),
        head: node.storage_head()?,
        coins,
        finalized: node.chain.finalized.is_some(),
        native_verified_at: monotonic()?,
    })
}

fn second_payment_ready(node: &Observation, input: Hash) -> bool {
    node.finalized
        && !node.coins.iter().any(|(id, _, _, _)| *id == input)
        && node.coins.iter().any(|(_, owner, amount, ready)| {
            *owner == public(14) && *amount == crate::Amount(100) && *ready
        })
}
fn pay(
    app: &mut wallet_app::App,
    options: &Options,
    recipient: String,
    input: Option<Hash>,
) -> Result<Sample> {
    let preview = app.act(wallet_app::Action::Prepare {
        request: json!({
        "inputs":input.map(|id|vec![id]),"outputs":[{"owner":recipient,"amount":"100"}],
        "remote":null,"fee":"0","valid_for_blocks":8,"valid_through":null}),
    })?;
    let signed = app.act(wallet_app::Action::Sign {
        review_id: serde_json::from_value(preview["review_id"].clone())
            .map_err(|e| e.to_string())?,
        review_commitment: serde_json::from_value(preview["review_commitment"].clone())
            .map_err(|e| e.to_string())?,
    })?;
    let intent = serde_json::from_value(signed["intent_id"].clone()).map_err(|e| e.to_string())?;
    let commands: Vec<crate::Command> =
        serde_json::from_value(signed["commands"].clone()).map_err(|e| e.to_string())?;
    let [crate::Command::Spend(command)] = commands.as_slice() else {
        return Err("ordinary payment command shape".into());
    };
    require(
        command.intent.inputs.len() == 1,
        "ordinary payment must consume one exact input",
    )?;
    let selected = command.intent.inputs[0];
    require(
        input.is_none_or(|expected| expected == selected),
        "next payment did not consume original recipient output",
    )?;
    let before = Store::open_inspection(&options.ledger, &options.authority, options.currency)?
        .storage_head()?;
    // The first signed submission clock precedes admission and its queue write.
    let submitted = monotonic()?;
    let local_sample = options
        .ledger
        .parent()
        .ok_or("fixture parent")?
        .join(format!(
            "submission-{}.json",
            options
                .ledger
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("actor name")?
        ));
    let mut recorded = json!({"intent":intent,"input":selected,"submitted":submitted,
        "queued":null,"queue_error":null,"recipient_completion":null,"fixture_only":true});
    atomic(&local_sample, &recorded, 64 * 1024)?;
    let result = app.act(wallet_app::Action::Submit { intent });
    let queued = monotonic()?;
    recorded["queued"] = if result.is_ok() {
        json!(queued)
    } else {
        Value::Null
    };
    recorded["queue_error"] = json!(result.as_ref().err());
    atomic(&local_sample, &recorded, 64 * 1024)?;
    let ack = result?;
    require(
        ack["included"] == false && ack["finalized"] == false,
        "wallet acknowledgment claimed inclusion or finality",
    )?;
    let node = Store::open_inspection(&options.ledger, &options.authority, options.currency)?;
    require(
        node.storage_head()? == before && node.chain.ledger.coins.contains_key(&selected),
        "wallet queue changed Native ledger or consumed its input",
    )?;
    Ok(Sample {
        intent,
        input: selected,
        submitted,
        queued,
    })
}
impl Actor {
    fn run(
        mut self,
        stop: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
        deadline: f64,
    ) -> Result<Stopped> {
        let mut timing = Vec::new();
        let mut scheduling = Vec::new();
        CARRIAGE_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
        let result = (|| {
            let _lease = Lease::acquire(
                Path::new(self.transport["state"].as_str().ok_or("transport state")?),
                "Service",
            )?;
            let mut app = self.wallet.take().map(wallet_app::App::open).transpose()?;
            if let Some(app) = &mut app {
                app.act(wallet_app::Action::Init {})?;
            }
            let mut cursor = None;
            let mut seen = Vec::new();
            let mut paused = false;
            let mut turns = 0;
            loop {
                require(
                    !failed.load(Ordering::Acquire),
                    "another wallet actor failed; retain fixture",
                )?;
                require(
                    monotonic()? < deadline,
                    "whole ordinary wallet cycle deadline exhausted",
                )?;
                if stop.load(Ordering::Acquire) {
                    let wallet = app.as_ref().map(|app| app.saved.clone());
                    drop(app);
                    drop(self.runtime.take());
                    let node = Store::open_inspection(
                        &self.options.ledger,
                        &self.options.authority,
                        self.options.currency,
                    )?;
                    return Ok(Stopped {
                        head: node.storage_head()?,
                        wallet,
                    });
                }
                while let Ok(job) = self.receiver.try_recv() {
                    match job {
                        Job::Availability {
                            paused: next,
                            reply,
                        } => {
                            require(
                                app.is_none(),
                                "fault pause must not control an owner wallet",
                            )?;
                            paused = next;
                            let result = observe(&self.options);
                            let error = result.as_ref().err().cloned();
                            reply.send(result).map_err(|e| e.to_string())?;
                            if let Some(error) = error {
                                return Err(error);
                            }
                        }
                        Job::Observe(reply) => {
                            let started = monotonic()?;
                            let result = observe(&self.options);
                            require(timing.len() < 1024, "actor timing record bound")?;
                            timing.push(json!({"phase":"controller_observe","seconds":monotonic()? - started,
                                "native_verified_at":result.as_ref().ok().map(|node|node.native_verified_at),
                                "observation_error":result.as_ref().err()}));
                            let error = result.as_ref().err().cloned();
                            reply.send(result).map_err(|e| e.to_string())?;
                            if let Some(error) = error {
                                return Err(error);
                            }
                        }
                        Job::Pay {
                            recipient,
                            input,
                            reply,
                        } => {
                            let started = monotonic()?;
                            let result = pay(
                                app.as_mut().ok_or("this actor has no owner wallet")?,
                                &self.options,
                                recipient,
                                input,
                            );
                            require(timing.len() < 1024, "actor timing record bound")?;
                            timing.push(
                                json!({"phase":"wallet_payment","seconds":monotonic()? - started}),
                            );
                            let error = result.as_ref().err().cloned();
                            reply.send(result).map_err(|e| e.to_string())?;
                            if let Some(error) = error {
                                return Err(error);
                            }
                        }
                    }
                    require(
                        monotonic()? < deadline,
                        "wallet operation exceeded original cycle deadline",
                    )?;
                }
                if paused {
                    thread::sleep(Duration::from_millis(55));
                    continue;
                }
                require(
                    turns < 192,
                    "ordinary wallet actor iteration budget exhausted",
                )?;
                turns += 1;
                let started = monotonic()?;
                let tick = directory_ledger_turn(
                    &self.options,
                    &self.transport,
                    &mut self.runtime,
                    &mut cursor,
                    &mut seen,
                );
                require(timing.len() < 1024, "actor timing record bound")?;
                timing.push(json!({"phase":"ordinary_directory_ledger_turn","seconds":monotonic()? - started,
                    "height":tick.as_ref().ok().and_then(|v|v.get("local_height")),"error":tick.as_ref().err()}));
                let observation = tick?;
                require(
                    observation["transport_attempt_errors"]
                        .as_array()
                        .is_some_and(Vec::is_empty),
                    "ordinary directory contact refused",
                )?;
                if let Some(runtime) = &self.runtime {
                    let controls = runtime.current_controls()?;
                    CARRIAGE_TRACE.with(|trace| -> Result<()> {
                        let mut trace = trace.borrow_mut();
                        let records = trace.as_mut().ok_or("missing diagnostic trace")?;
                        require(records.len() < 4096, "diagnostic carriage record bound")?;
                        records.push(json!({"phase":"native-controls","at":monotonic()?,"observation":controls}));
                        Ok(())
                    })?;
                    if scheduling.len() == 32 {
                        scheduling.remove(0);
                    }
                    scheduling.push(runtime.scheduling_observation()?);
                }
                require(
                    monotonic()? < deadline,
                    "ordinary Native tick exceeded original cycle deadline",
                )?;
                thread::sleep(Duration::from_millis(55));
            }
        })();
        if result.is_err() {
            failed.store(true, Ordering::Release);
        }
        let carriage = take_work_trace();
        atomic(
            &self
                .options
                .ledger
                .parent()
                .ok_or("fixture parent")?
                .join(format!(
                    "carriage-{}.json",
                    self.options
                        .ledger
                        .file_name()
                        .and_then(|v| v.to_str())
                        .ok_or("actor name")?
                )),
            &json!({"events":carriage,"fixture_only":true,"signing_authority":false}),
            4 * 1024 * 1024,
        )?;
        let path = self
            .options
            .ledger
            .parent()
            .ok_or("actor fixture parent")?
            .join(format!(
                "work-{}.json",
                self.options
                    .ledger
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or("actor directory name")?
            ));
        let saved = atomic(
            &path,
            &json!({"timing":timing,"scheduling":scheduling,"error":result.as_ref().err(),"fixture_only":true}),
            128 * 1024,
        );
        if result.is_ok() {
            saved?;
        }
        result
    }
}
fn wait<T>(receiver: Receiver<Result<T>>, deadline: f64) -> Result<T> {
    let remaining = deadline - monotonic()?;
    require(
        remaining > 0.0,
        "ordinary wallet controller deadline exhausted",
    )?;
    receiver
        .recv_timeout(Duration::from_secs_f64(remaining))
        .map_err(|e| e.to_string())?
}
fn observations(workers: &[Worker], deadline: f64) -> Result<Vec<Observation>> {
    let mut receivers = Vec::new();
    for worker in workers {
        let (sender, receiver) = mpsc::channel();
        worker
            .sender
            .send(Job::Observe(sender))
            .map_err(|e| e.to_string())?;
        receivers.push(receiver);
    }
    receivers
        .into_iter()
        .map(|receiver| wait(receiver, deadline))
        .collect()
}
fn payment(
    worker: &Worker,
    recipient: String,
    input: Option<Hash>,
    deadline: f64,
) -> Result<Sample> {
    let (sender, receiver) = mpsc::channel();
    worker
        .sender
        .send(Job::Pay {
            recipient,
            input,
            reply: sender,
        })
        .map_err(|e| e.to_string())?;
    wait(receiver, deadline)
}
fn availability(worker: &Worker, paused: bool, deadline: f64) -> Result<Observation> {
    let (sender, receiver) = mpsc::channel();
    worker
        .sender
        .send(Job::Availability {
            paused,
            reply: sender,
        })
        .map_err(|e| e.to_string())?;
    wait(receiver, deadline)
}

fn custody_inventory(
    root: &Path,
    actor: usize,
) -> Result<std::collections::BTreeMap<PathBuf, String>> {
    let mut pending = ["ledger", "signer", "caller", "runtime", "transport"]
        .into_iter()
        .map(|kind| root.join(format!("{kind}-{actor}")))
        .collect::<Vec<_>>();
    let mut result = std::collections::BTreeMap::new();
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(
            !meta.file_type().is_symlink(),
            "fault inventory symlink refused",
        )?;
        if meta.is_dir() {
            for entry in fs::read_dir(&path).map_err(|e| e.to_string())? {
                pending.push(entry.map_err(|e| e.to_string())?.path());
            }
        } else {
            require(meta.is_file(), "fault inventory regular file required")?;
            let raw = files::private_read_with_limit(&path, 32 * 1024 * 1024)?;
            result.insert(path, hex::encode(Sha256::digest(&raw)));
        }
    }
    Ok(result)
}
fn setup(
    root: &Path,
    deadline: f64,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    rules: &str,
) -> Result<(Vec<Worker>, Vec<u8>, Hash)> {
    let mut genesis = crate::tests::bootstrap();
    if crate::paged_bft::is_profile(rules) {
        genesis.currency.cap = crate::Amount::TOTAL_SUPPLY;
        genesis.currency.block_reward = rld_pow::subsidy(1)?;
        genesis.currency.signature = signature(1, &genesis.currency.bytes()?);
    }
    for admission in &mut genesis.admissions {
        admission.currency = genesis.currency.id()?;
        admission.rules = rules.into();
        if crate::paged_bft::is_profile(rules) {
            admission.value_rules = Some(crate::paged_bft::rules_hash_for(rules)?);
        }
        admission.signature = signature(1, &admission.bytes()?);
    }
    let currency = genesis.currency.id()?;
    let region = genesis.admissions[0].id()?;
    let mut seeds = (2u8..6).collect::<Vec<_>>();
    seeds.sort_by_key(|seed| public(*seed));
    let mut nodes = Vec::new();
    let mut ids = Vec::new();
    for n in 0..4 {
        nodes.push(Store::create(
            &root.join(format!("ledger-{n}")),
            genesis.clone(),
            region,
            &public(1),
            currency,
        )?);
        let identity = initialize(
            &root.join(format!("transport-{n}")),
            &currency.to_hex(),
            &region.to_hex(),
            "public-no-value-wallet-cycle",
        )?;
        ids.push(
            identity["node_id"]
                .as_str()
                .ok_or("fixture identity")?
                .to_owned(),
        );
    }
    let mut prepared = Vec::new();
    for n in 0..4 {
        let transport = json!({"format":MESH,"network":currency,"state":root.join(format!("transport-{n}")),
            "contacts":(0..4).filter(|p|*p!=n).map(|p|json!({"peer":ids[p],
                "inbox":root.join(format!("spool-{p}-{n}")),"outbox":root.join(format!("spool-{n}-{p}"))})).collect::<Vec<_>>()});
        let signer = root.join(format!("signer-{n}"));
        let agent = bft::Agent::create(&signer, &nodes[n], public(seeds[n]))?;
        let caller = directory(&root.join(format!("caller-{n}")))?.join("head.json");
        let state = bft_client::State {
            format: bft_client::FORMAT.into(),
            binding: agent.journal.binding.clone(),
            head: agent.head()?,
            pending: None,
            outbox: None,
        };
        drop(agent);
        crate::keystore::private_create(&caller, &files::canonical(&state)?)?;
        let key = root.join(format!("public-validator-key-{n}.json"));
        crate::keystore::private_create(
            &key,
            &serde_json::to_vec(&json!({"secret_key":hex::encode([seeds[n];32])}))
                .map_err(|e| e.to_string())?,
        )?;
        let config = json!({"format":bft_client::FORMAT,"state":directory(&root.join(format!("runtime-{n}")))?,
            "signer_dir":signer,"head_file":caller,"key_file":key,"key":public(seeds[n]),"miner":public(10),
            "validators":seeds.iter().enumerate().map(|(p,s)|json!({"key":public(*s),"node_id":ids[p]})).collect::<Vec<_>>(),
            "block_interval":0.5,"round_timeout":5.0,"stop_height":12});
        let path = root.join(format!("config-{n}.json"));
        atomic(&path, &config, 64 * 1024)?;
        let runtime = super::super::bft::Runtime::open(&path, &nodes[n], &transport)?;
        let options = Options {
            ledger: root.join(format!("ledger-{n}")),
            authority: public(1),
            currency,
            mesh_config: None,
            bft_config: None,
            listen: "127.0.0.1:0"
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?,
            miner: None,
            interval: 0.05,
            insecure_tcp: false,
        };
        let wallet = if n == 0 || n == 3 {
            let seed = if n == 3 { 10 } else { 11 };
            let key = root.join(format!("public-wallet-key-{n}.json"));
            crate::keystore::private_create(
                &key,
                &serde_json::to_vec(&json!({"secret_key":hex::encode([seed;32])}))
                    .map_err(|e| e.to_string())?,
            )?;
            Some(wallet_app::Options {
                ledger: options.ledger.clone(),
                authority: public(1),
                currency,
                wallet: root.join(format!("wallet-{n}")),
                heads: root.join(format!("wallet-caller-{n}")),
                owner: public(seed),
                expected: None,
                key: Some(key),
                encrypted_key: None,
                passphrase: None,
                backup_dir: None,
                miner: None,
            })
        } else {
            None
        };
        let (sender, receiver) = mpsc::channel();
        prepared.push((
            sender,
            Actor {
                options,
                transport,
                runtime: Some(runtime),
                wallet,
                receiver,
            },
        ));
    }
    drop(nodes);
    let workers = prepared
        .into_iter()
        .map(|(sender, actor)| {
            let stop = stop.clone();
            let failed = failed.clone();
            Worker {
                sender,
                thread: thread::spawn(move || actor.run(stop, failed, deadline)),
            }
        })
        .collect();
    Ok((workers, seeds, currency))
}

#[test]
fn native_observation_clock_precedes_delayed_reply_and_wrong_root_has_no_observation() {
    let started = monotonic().unwrap();
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-native-payment-clock-{}", random().unwrap())),
    )
    .unwrap();
    eprintln!("Fresh Native observation clock fixture: {}", root.display());
    let genesis = crate::tests::bootstrap();
    let currency = genesis.currency.id().unwrap();
    let node = Store::create(
        &root.join("ledger"),
        genesis.clone(),
        genesis.admissions[0].id().unwrap(),
        &public(1),
        currency,
    )
    .unwrap();
    let head = node.storage_head().unwrap();
    drop(node);
    let mut options = Options {
        ledger: root.join("ledger"),
        authority: public(1),
        currency,
        mesh_config: None,
        bft_config: None,
        listen: "127.0.0.1:0".parse().unwrap(),
        miner: None,
        interval: 0.5,
        insecure_tcp: false,
    };
    let requested_at = monotonic().unwrap();
    let observed = observe(&options).unwrap();
    let response_ready = monotonic().unwrap();
    assert!(observed.native_verified_at >= requested_at);
    assert!(observed.native_verified_at <= response_ready);
    assert_eq!(observed.height, 0);
    assert!(!observed.finalized && observed.coins.is_empty());
    assert!(!second_payment_ready(&observed, Hash::ZERO));
    // Delay only release of an already fully Native-checked observation. Its
    // clock must not be rebased to a later controller/other-replica response.
    thread::sleep(Duration::from_millis(80));
    let (sender, receiver) = mpsc::channel();
    sender.send(Ok(observed)).unwrap();
    let received = wait(receiver, started + 60.0).unwrap();
    assert!(received.native_verified_at <= response_ready);
    assert!(monotonic().unwrap() - received.native_verified_at >= 0.08);
    let cold = Store::open_pinned(&options.ledger, &public(1), currency, head).unwrap();
    assert_eq!(cold.storage_head().unwrap(), head);
    assert!(cold.chain.ledger.coins.is_empty());
    drop(cold);
    options.authority = public(99);
    assert!(
        observe(&options).is_err(),
        "wrong root released an observation"
    );
    assert!(monotonic().unwrap() - started < 60.0);
}

#[test]
fn four_native_replicas_finalize_first_payment_and_actual_recipient_next_spend() {
    ordinary_cycle(bft::RULES);
}

#[test]
fn four_packed_native_replicas_finalize_first_payment_and_actual_recipient_next_spend() {
    ordinary_cycle(crate::paged_bft::PACKED_RULES);
}

fn ordinary_cycle(rules: &str) {
    cycle_with_unavailable_validator(rules, None);
}

#[test]
fn three_packed_validators_pay_twice_while_fourth_paused_then_catch_up_and_cold_verify() {
    cycle_with_unavailable_validator(crate::paged_bft::PACKED_RULES, Some(1));
}

fn cycle_with_unavailable_validator(rules: &str, unavailable: Option<usize>) {
    assert!(
        unavailable.is_none_or(|actor| actor == 1),
        "predeclared fault actor differs"
    );
    let started = monotonic().unwrap();
    let deadline = started + 120.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-four-wallet-{}", random().unwrap())),
    )
    .unwrap();
    eprintln!("Fresh ordinary wallet cycle: {}", root.display());
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let (workers, seeds, currency) =
        setup(&root, deadline, stop.clone(), failed.clone(), rules).unwrap();
    let mut samples = Vec::new();
    let mut fault = Value::Null;
    let mut cold_envelope_counts = Vec::new();
    let result = (|| -> Result<()> {
        loop {
            let observed = observations(&workers, deadline)?;
            if observed
                .iter()
                .all(|node| node.height >= 3 && node.finalized)
            {
                break;
            }
            thread::sleep(Duration::from_millis(55));
        }
        let frozen = if let Some(actor) = unavailable {
            require(
                actor == 1,
                "fault actor must be fixed before fixture creation",
            )?;
            let observed = availability(&workers[actor], true, deadline)?;
            fault = json!({"kind":"one-logical-validator-consensus-and-transport-paused","actor":actor,
                "paused_at":monotonic()?,"height":observed.height,"head":observed.head,"resumed_at":null,
                "custody_unchanged_before_resume":false,"three_live_replicas_second_payment_ready":false,
                "process_crash_qualification":false,"independent_operations":false});
            Some((observed, custody_inventory(&root, actor)?))
        } else {
            None
        };
        let first = payment(&workers[3], public(11), None, deadline)?;
        samples.push(
            json!({"intent":first.intent,"input":first.input,"submitted":first.submitted,
            "queued":first.queued,"queue_age_seconds":first.queued-first.submitted,
            "recipient_actor":FIRST_RECIPIENT,"recipient_native_verified_at":null,
            "recipient_native_latency_seconds":null,"recipient_finalized_spendable":null,"latency_seconds":null}),
        );
        let input = loop {
            let observed = observations(&workers, deadline)?;
            if let Some((id, _, _, _)) =
                observed[FIRST_RECIPIENT]
                    .coins
                    .iter()
                    .find(|(_, owner, amount, ready)| {
                        *owner == public(11)
                            && *amount == crate::Amount(100)
                            && *ready
                            && observed[FIRST_RECIPIENT].finalized
                    })
            {
                let verified = observed[FIRST_RECIPIENT].native_verified_at;
                samples[0]["recipient_native_verified_at"] = json!(verified);
                samples[0]["recipient_native_latency_seconds"] = json!(verified - first.submitted);
                break *id;
            }
            thread::sleep(Duration::from_millis(55));
        };
        let ready = monotonic()?;
        samples[0]["recipient_finalized_spendable"] = json!(ready);
        samples[0]["latency_seconds"] = json!(ready - first.submitted);
        let second = payment(&workers[0], public(14), Some(input), deadline)?;
        samples.push(
            json!({"intent":second.intent,"input":second.input,"submitted":second.submitted,
            "queued":second.queued,"queue_age_seconds":second.queued-second.submitted,
            "recipient_actor":SECOND_RECIPIENT,"recipient_native_verified_at":null,
            "recipient_native_latency_seconds":null,"replica_native_verified_at":[null,null,null,null],
            "all_replicas_finalized_spendable":null,"latency_seconds":null}),
        );
        let mut resumed = unavailable.is_none();
        loop {
            let observed = observations(&workers, deadline)?;
            for (n, node) in observed.iter().enumerate() {
                if second_payment_ready(node, input)
                    && samples[1]["replica_native_verified_at"][n].is_null()
                {
                    samples[1]["replica_native_verified_at"][n] = json!(node.native_verified_at);
                    if n == SECOND_RECIPIENT {
                        samples[1]["recipient_native_verified_at"] = json!(node.native_verified_at);
                        samples[1]["recipient_native_latency_seconds"] =
                            json!(node.native_verified_at - second.submitted);
                    }
                }
            }
            if let Some(actor) = unavailable {
                if !resumed
                    && observed
                        .iter()
                        .enumerate()
                        .filter(|(n, _)| *n != actor)
                        .all(|(_, node)| second_payment_ready(node, input))
                {
                    let (prior, inventory) =
                        frozen.as_ref().ok_or("missing frozen fault custody")?;
                    require(
                        observed[actor].height == prior.height
                            && observed[actor].head == prior.head,
                        "paused validator advanced Native state",
                    )?;
                    require(
                        custody_inventory(&root, actor)? == *inventory,
                        "paused validator custody bytes changed",
                    )?;
                    fault["three_live_replicas_second_payment_ready"] = json!(true);
                    fault["custody_unchanged_before_resume"] = json!(true);
                    availability(&workers[actor], false, deadline)?;
                    fault["resumed_at"] = json!(monotonic()?);
                    resumed = true;
                }
            }
            if observed
                .iter()
                .all(|node| second_payment_ready(node, input))
            {
                break;
            }
            thread::sleep(Duration::from_millis(55));
        }
        let ready = monotonic()?;
        samples[1]["all_replicas_finalized_spendable"] = json!(ready);
        samples[1]["latency_seconds"] = json!(ready - second.submitted);
        if unavailable.is_some() {
            require(
                resumed
                    && fault["three_live_replicas_second_payment_ready"] == true
                    && fault["custody_unchanged_before_resume"] == true
                    && !fault["resumed_at"].is_null(),
                "fault lifecycle did not complete three-live payment before restoration",
            )?;
        }
        require(
            monotonic()? < deadline,
            "payment completion exceeded whole original deadline",
        )
    })();
    stop.store(true, Ordering::Release);
    let mut stopped = Vec::new();
    let mut worker_errors = Vec::new();
    for (n, worker) in workers.into_iter().enumerate() {
        match worker.thread.join() {
            Ok(Ok(state)) => stopped.push(state),
            Ok(Err(error)) => worker_errors.push(json!({"actor":n,"error":error})),
            Err(_) => worker_errors.push(json!({"actor":n,"error":"wallet actor panicked"})),
        }
    }
    let result = result.and_then(|_| {
        require(
            worker_errors.is_empty() && stopped.len() == 4,
            &format!("wallet actor closure failed: {worker_errors:?}"),
        )?;
        let mut prefixes = Vec::new();
        for n in 0..4 {
            let before = unavailable
                .map(|_| custody_inventory(&root, n))
                .transpose()?;
            let node = Store::open_pinned(
                &root.join(format!("ledger-{n}")),
                &public(1),
                currency,
                stopped[n].head,
            )?;
            let caller = bft_client::Client::lock(
                &root.join(format!("caller-{n}/head.json")),
                &root.join(format!("signer-{n}")),
                public(seeds[n]),
                bft_client::FORMAT.into(),
                &node,
            )?;
            let state = caller.read()?;
            require(
                state.pending.is_none() && state.outbox.is_none(),
                "BFT caller still has pending custody",
            )?;
            let (_, status) =
                bft::Agent::inspect_with_status(&root.join(format!("signer-{n}")), &node)?;
            require(
                status.head == state.head,
                "cold BFT signer and caller heads differ",
            )?;
            if unavailable.is_some() {
                let raw = files::private_read_with_limit(
                    &root.join(format!("runtime-{n}/state.json")),
                    crate::bft_runtime_archive::MAX_STATE,
                )?;
                let archive = crate::bft_runtime_archive::Archive::decode(&raw)?;
                let records = archive.runtime.messages.values().collect::<Vec<_>>();
                let mut count = 0;
                for batch in records.chunks(crate::bft_network::MAX_COLD_BATCH) {
                    let wires = batch
                        .iter()
                        .map(|record| {
                            serde_json::from_value(archive.envelope(record)?)
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let checked = crate::bft_network::check_cold_batch(wires, &node)?;
                    require(
                        checked.len() == batch.len(),
                        "cold fault archive omitted an envelope",
                    )?;
                    for (record, checked) in batch.iter().zip(checked) {
                        require(
                            record.value == checked.value,
                            "cold fault archive value differs",
                        )?;
                        count += 1;
                    }
                }
                require(
                    count == archive.runtime.messages.len(),
                    "cold fault archive incomplete",
                )?;
                cold_envelope_counts.push(count);
            }
            if let Some(saved) = &stopped[n].wallet {
                let owner = if n == 3 { public(10) } else { public(11) };
                let client = wallet_client::Client::lock(
                    &root.join(format!("wallet-caller-{n}")),
                    &root.join(format!("wallet-{n}")),
                    owner,
                    &node,
                )?;
                require(
                    client.read()? == *saved && saved.pending.is_none(),
                    "cold wallet caller head differs",
                )?;
                let wallet =
                    crate::wallet_agent::Agent::open(&root.join(format!("wallet-{n}")), &node)?;
                let view = wallet.view(&node, saved.head.ok_or("missing wallet head")?)?;
                require(
                    wallet.journal.records.len() == 1
                        && view.reserved_owned_outputs == crate::Amount::ZERO
                        && view.signed[0].state == "INCLUDED_IN_LOCAL_LEDGER",
                    "original wallet approval not included exactly once",
                )?;
            }
            require(
                node.chain.ledger.coins.values().any(|coin| {
                    coin.payment.owner == public(14) && coin.payment.amount == crate::Amount(100)
                }),
                "cold second payment output absent",
            )?;
            let empty = ["proxima", "andromeda"]
                .into_iter()
                .map(|name| crate::Chain::new(node.trust.named(name)?, &node.trust))
                .collect::<Result<Vec<_>>>()?;
            crate::conservation(&[node.chain.clone(), empty[0].clone(), empty[1].clone()])?;
            prefixes.push(
                node.blocks()?
                    .map(|block| block.and_then(|block| block.header.id()))
                    .collect::<Result<Vec<_>>>()?,
            );
            if let Some(before) = before {
                require(
                    custody_inventory(&root, n)? == before,
                    "fault cold verification changed private custody",
                )?;
            }
        }
        let common = prefixes
            .iter()
            .map(Vec::len)
            .min()
            .ok_or("no certified prefixes")?;
        require(
            prefixes
                .iter()
                .all(|blocks| blocks[..common] == prefixes[0][..common]),
            "certified replica prefixes conflict",
        )?;
        require(
            monotonic()? < deadline,
            "whole wallet cold closure exceeded original deadline",
        )
    });
    let completed_at = monotonic().unwrap();
    for sample in &mut samples {
        sample["report_age_seconds"] = json!(completed_at - sample["submitted"].as_f64().unwrap());
        sample["recipient_pending_age_seconds"] =
            if sample["recipient_native_verified_at"].is_null() {
                sample["report_age_seconds"].clone()
            } else {
                Value::Null
            };
    }
    atomic(&root.join("payment-observations.json"), &json!({"samples":samples,"passed":result.is_ok(),
        "error":result.as_ref().err(),"worker_errors":worker_errors,"whole_seconds":monotonic().unwrap()-started,
        "recipient_actors":[FIRST_RECIPIENT,SECOND_RECIPIENT],"reported_at":completed_at,
        "fault":fault,"fault_cold_envelope_counts":cold_envelope_counts,
        "independent_operations":false,"latency_percentiles_qualified":false,"fixture_only":true}), 64*1024).unwrap();
    // Retain the complete private sample scope on both success and failure.
    result.unwrap();
}
