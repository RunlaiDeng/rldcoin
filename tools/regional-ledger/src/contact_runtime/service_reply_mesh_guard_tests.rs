//! Isolated original-deadline/cancellation/fatal identity guards. No TLS or value execution.
use super::*;
use std::io::Write;

const GUARD_FORMAT: &str = "RLD-REPLY-MESH-HELPER-GUARDS-V1";
const GUARD_SCOPE: &str = "reply_mesh_guards_scope=";
const GUARD_RESULT: &str = "reply_mesh_guards_result=";

fn refusal(result: Result<Node>) -> Result<String> {
    match result {
        Err(error) => Ok(error),
        Ok(node) => {
            drop(node);
            Err("reply guard unexpectedly obtained a Node".into())
        }
    }
}
struct StopReset(bool);
impl Drop for StopReset {
    fn drop(&mut self) {
        STOP.store(self.0, Ordering::Release);
    }
}
struct NoneWitness {
    original: f64,
    observed: f64,
    released: f64,
}
struct GuardWorker {
    returned: mpsc::SyncSender<()>,
    worker: Option<std::thread::JoinHandle<Result<NoneWitness>>>,
}
impl GuardWorker {
    fn join(&mut self) -> Result<NoneWitness> {
        self.worker
            .take()
            .ok_or("reply guard worker joined twice")?
            .join()
            .map_err(|_| "reply guard worker panicked")?
    }
}
impl Drop for GuardWorker {
    fn drop(&mut self) {
        // Send even during unwind; every owned worker is joined before STOP reset.
        let _ = self.returned.try_send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn remaining(deadline: f64) -> Result<Duration> {
    let left = deadline - monotonic()?;
    require(left > 0.0, "reply guard original whole10 exhausted")?;
    Ok(Duration::from_secs_f64(left))
}
fn after_real_none(
    f: &ReplyFixture,
    scope_deadline: f64,
    stop: bool,
) -> Result<(String, NoneWitness)> {
    within(scope_deadline)?;
    let original = monotonic()? + 3.0;
    require(
        original < scope_deadline,
        "reply guard no original3 within whole10",
    )?;
    let held = Lease::acquire(
        Path::new(f.configs[0]["state"].as_str().ok_or("guard source state")?),
        "Mesh",
    )?;
    let (observer_reset, observed) = install_reply_mesh_defer_observer()?;
    let stop_reset = StopReset(STOP.load(Ordering::Acquire));
    let (returned, return_rx) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("reply helper guard Mesh owner".into())
        .spawn(move || -> Result<NoneWitness> {
            let (phase, deadline, at) = observed
                .recv_timeout(remaining(scope_deadline)?)
                .map_err(|e| format!("reply guard actual None absent: {e}"))?;
            require(
                phase == "reply-custody" && deadline == original && at < original,
                "reply guard original actual None binding",
            )?;
            if stop {
                STOP.store(true, Ordering::Release);
                return_rx
                    .recv_timeout(remaining(scope_deadline)?)
                    .map_err(|e| format!("reply guard source return absent: {e}"))?;
            }
            drop(held);
            Ok(NoneWitness {
                original: deadline,
                observed: at,
                released: monotonic()?,
            })
        })
        .map_err(|e| format!("reply guard worker spawn refused: {e}"))?;
    let mut owner = GuardWorker {
        returned,
        worker: Some(worker),
    };
    let operation =
        reply_node_before_deadline(&f.configs[0], original, &f.ids[0], &f.currency.to_hex());
    let source_returned = monotonic();
    let notice = owner.returned.try_send(());
    let joined = owner.join();
    // Both worker release/join and STOP restoration precede propagating any error.
    drop(stop_reset);
    drop(observer_reset);
    let error = refusal(operation)?;
    let witness = joined.map_err(|e| format!("reply guard primary={error}; worker={e}"))?;
    if stop {
        notice.map_err(|e| format!("reply guard return notice: {e}"))?;
    }
    let returned_at = source_returned?;
    require(
        witness.observed <= returned_at && returned_at < witness.original,
        "reply guard cancellation/fatal result outside original helper deadline",
    )?;
    if stop {
        require(
            returned_at <= witness.released,
            "reply guard released held Mesh before STOP refusal",
        )?;
    }
    within(scope_deadline)?;
    Ok((error, witness))
}
fn intact_pending(root: &Path, f: &ReplyFixture, deadline: f64) -> Result<()> {
    reply_native_zero(root, f, deadline)?;
    let source = Node::open(&f.configs[0])?;
    require(
        source.received_frames()?.is_empty(),
        "reply guard fabricated local receive",
    )?;
    drop(source);
    let raw = files::private_read_with_limit(
        &root.join("source-mesh/native-mesh-state.json"),
        32 * 1024 * 1024,
    )?;
    let source = state_image(&raw, f.currency, &f.ids[0])?;
    require(
        source["state"]["cursor"] == f.source_cursor
            && source["state"]["messages"]
                .as_object()
                .is_some_and(|m| m.len() == 1 && m.contains_key(&f.source_packet))
            && source["state"]["receipts"] == f.source_before["state"]["receipts"]
            && source["state"]["archives"] == f.source_before["state"]["archives"]
            && source["state"]["peer_inventory"] == f.source_before["state"]["peer_inventory"]
            && source["frames"].as_object().is_some_and(|m| {
                m.len() == 1
                    && m.values()
                        .any(|v| v["frame"] == STANDARD.encode(&f.source_frame))
            }),
        "reply guard changed original frame/cursor/receipt/suppression",
    )?;
    within(deadline)
}
fn guards(root: &Path, started: f64, deadline: f64) -> Result<Value> {
    require(
        !STOP.load(Ordering::Acquire),
        "reply guards process already stopped",
    )?;
    for original in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        require(
            refusal(reply_node_before_deadline(
                &Value::Null,
                original,
                "unused",
                "unused",
            ))? == "TLS_TIMEOUT: invalid original reply custody deadline",
            "reply invalid deadline did not refuse before open",
        )?;
    }
    require(
        refusal(reply_node_before_deadline(
            &Value::Null,
            started - 1.0,
            "unused",
            "unused",
        ))? == "TLS_TIMEOUT: original reply custody deadline exhausted; retain complete evidence",
        "reply expired deadline did not refuse before open",
    )?;
    {
        let reset = StopReset(STOP.swap(true, Ordering::AcqRel));
        let result = refusal(reply_node_before_deadline(
            &Value::Null,
            monotonic()? + 3.0,
            "unused",
            "unused",
        ));
        drop(reset);
        require(
            result? == "outgoing reply custody cancelled; retain complete evidence",
            "reply preopen STOP not preserved",
        )?;
    }
    let valid_root = directory(&root.join("valid"))?;
    let valid = reply_fixture(&valid_root, deadline)?;
    let (stop_error, stop_witness) = after_real_none(&valid, deadline, true)?;
    require(
        stop_error == "outgoing reply custody cancelled; retain complete evidence",
        "reply real None STOP not preserved",
    )?;
    let network = valid.currency.to_hex();
    let identity_error = refusal(reply_node_before_deadline(
        &valid.configs[1],
        monotonic()? + 3.0,
        &valid.ids[0],
        &network,
    ))?;
    require(
        identity_error == "reply custody identity changed after original preparation",
        "reply valid alternate identity not refused",
    )?;
    require(
        valid.currency != Hash::ZERO,
        "reply guard alternate network must differ",
    )?;
    let network_error = refusal(reply_node_before_deadline(
        &valid.configs[0],
        monotonic()? + 3.0,
        &valid.ids[0],
        &Hash::ZERO.to_hex(),
    ))?;
    require(
        network_error == "reply custody identity changed after original preparation",
        "reply valid Node wrong expected network not refused",
    )?;
    intact_pending(&valid_root, &valid, deadline)?;
    let fatal_root = directory(&root.join("fatal"))?;
    let fatal = reply_fixture(&fatal_root, deadline)?;
    let damaged = fatal_root.join("source-mesh/native-mesh-state.json");
    let original = files::private_read_with_limit(&damaged, 32 * 1024 * 1024)?;
    crate::keystore::private_create(&fatal_root.join("original-mesh-state.retained"), &original)?;
    {
        let mut file = io(fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&damaged))?;
        io(file.write_all(b"invalid retained Mesh state; preserve this fresh refusal fixture"))?;
        io(file.sync_all())?;
    }
    let damaged_before = inventory(&fatal_root)?;
    let exact_fatal = refusal(Node::open(&fatal.configs[0]))?;
    require(
        !exact_fatal.is_empty()
            && !exact_fatal.starts_with("TLS_TIMEOUT:")
            && ![libc::EWOULDBLOCK, libc::EAGAIN]
                .iter()
                .any(|n| exact_fatal.starts_with(&format!("CONTACT_STORAGE_IO:{n}:"))),
        "reply fatal probe is not a distinct complete-open error",
    )?;
    let (reset, no_defer) = install_reply_mesh_defer_observer()?;
    let direct = refusal(reply_node_before_deadline(
        &fatal.configs[0],
        monotonic()? + 3.0,
        &fatal.ids[0],
        &fatal.currency.to_hex(),
    ));
    let no_defer_result = no_defer.try_recv();
    drop(reset);
    require(
        direct? == exact_fatal && matches!(no_defer_result, Err(mpsc::TryRecvError::Empty)),
        "reply direct fatal was changed or retried as None",
    )?;
    let (deferred, fatal_witness) = after_real_none(&fatal, deadline, false)?;
    require(
        deferred == exact_fatal,
        "reply real None release altered complete-open fatal error",
    )?;
    require(
        inventory(&fatal_root)? == damaged_before,
        "reply fatal guard changed damaged or retained evidence",
    )?;
    reply_native_zero(&fatal_root, &fatal, deadline)?;
    require(
        files::private_read_with_limit(
            &fatal_root.join("original-mesh-state.retained"),
            32 * 1024 * 1024,
        )? == original,
        "reply fatal guard lost exact original evidence",
    )?;
    require(!STOP.load(Ordering::Acquire), "reply guard STOP leaked")?;
    let errors = json!({"pre_stop":stop_error,"fatal":exact_fatal,"identity":identity_error,"network":network_error});
    reply_metadata(&root.join("guard-errors.json"), &errors)?;
    within(deadline)?;
    Ok(
        json!({"guard_cases":10,"actual_none_cases":2,"owned_workers_joined":true,
        "valid_pending_and_native_unchanged":true,"damaged_evidence_retained":true,
        "fatal_error_sha256":sha(exact_fatal.as_bytes()),"identity_error_sha256":sha(identity_error.as_bytes()),
        "network_error_sha256":sha(network_error.as_bytes()),"error_summary_sha256":sha(&files::private_read_with_limit(&root.join("guard-errors.json"),64*1024)?),
        "stop_actual_none_at":stop_witness.observed,"fatal_actual_none_at":fatal_witness.observed}),
    )
}
#[test]
#[ignore = "fresh reply helper guards; original10 normal,15 external stop only"]
fn outgoing_reply_custody_preserves_original_deadline_stop_identity_and_fatal_errors() -> Result<()>
{
    require(
        std::env::var(OPT_IN).as_deref() == Ok("1"),
        "reply retry candidate opt-in required",
    )?;
    let started = monotonic()?;
    let deadline = started + 10.0;
    let root = io(fs::canonicalize(std::env::temp_dir()))?
        .join(format!("rld-reply-mesh-guards-{}", random()?));
    match fs::symlink_metadata(&root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err("reply helper guards root not fresh".into()),
    }
    let root = directory(&root)?;
    let scope = json!({"format":GUARD_FORMAT,"root":root,"pid":std::process::id(),"started":started,
        "deadline":deadline,"stop_deadline":started+15.0,"guard_only_no_tls":true,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"native_authority":false,
        "whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    reply_metadata(&root.join("scope.json"), &scope)?;
    eprintln!("{GUARD_SCOPE}{scope}");
    let run = guards(&root, started, deadline).and_then(|mut value| {
        value["test_binary_sha256"] = json!(sha(&io(fs::read(io(std::env::current_exe())?))?));
        Ok(value)
    });
    let ended = monotonic();
    let result = run.and_then(|value| {
        require(
            ended.as_ref().map_err(Clone::clone)? < &deadline,
            "reply guard whole original10 exhausted",
        )?;
        Ok(value)
    });
    let mut outcome = json!({"format":GUARD_FORMAT,"root":root,"pid":std::process::id(),"passed":result.is_ok(),
        "started":started,"deadline":deadline,"stop_deadline":started+15.0,"ended":ended.as_ref().ok(),"elapsed_seconds":ended.as_ref().ok().map(|end| *end-started),
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"guard_only_no_tls":true,
        "native_authority":false,"whole_payment_pass":false,"payment_qualified":false,"mainnet":false});
    outcome.as_object_mut().ok_or("reply guards outcome object")?.extend(json!({
        "guard_cases":null,"actual_none_cases":null,"owned_workers_joined":null,
        "valid_pending_and_native_unchanged":null,"damaged_evidence_retained":null,
        "fatal_error_sha256":null,"identity_error_sha256":null,"network_error_sha256":null,
        "error_summary_sha256":null,"stop_actual_none_at":null,"fatal_actual_none_at":null,"test_binary_sha256":null
    }).as_object().ok_or("reply guards unknown details object")?.clone());
    if let Ok(value) = &result {
        outcome
            .as_object_mut()
            .ok_or("reply guards outcome object")?
            .extend(
                value
                    .as_object()
                    .ok_or("reply guards details object")?
                    .clone(),
            );
    }
    let failure_write = match &result {
        Err(error) => new_json(&root.join("private-failure.json"), &json!({"error":error})),
        Ok(_) => Ok(()),
    };
    let outcome_write = reply_metadata(&root.join("outcome.json"), &outcome);
    eprintln!("{GUARD_RESULT}{outcome}");
    result?;
    failure_write?;
    outcome_write
}
