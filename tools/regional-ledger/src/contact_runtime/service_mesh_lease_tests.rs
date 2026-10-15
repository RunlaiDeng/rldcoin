//! Passive wrapper diagnostics only: real Mesh lock primitive, no packet/ledger authority.
use super::super::{mesh_operation, mesh_role};
use super::*;
use crate::contact_runtime::{directory, random, Lease};
const FORMAT: &str = "RLD-MESH-WRAPPER-OBSERVATION-UNIT-V1";
fn now() -> f64 {
    super::super::monotonic().unwrap()
}
fn inside(deadline: f64) {
    assert!(now() < deadline, "original wrapper unit scope exhausted");
}
#[test]
#[ignore = "one fresh real Mesh lease primitive and passive collector scope; no Native value"]
fn passive_mesh_lease_cycle_and_disabled_mode_preserve_real_lock() {
    assert_eq!(std::env::var("RLD_MESH_WRAPPER_UNIT").as_deref(), Ok("1"));
    let started = now();
    let deadline = started + 10.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rld-passive-mesh-wrapper-{}", random().unwrap())),
    )
    .unwrap();
    let scope = json!({"format":FORMAT,"root":root,"pid":std::process::id(),
        "started":started,"deadline":deadline,"scope_seconds":10,"external_stop_seconds":15,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "test_source_sha256":hex::encode(Sha256::digest(include_bytes!("service_mesh_lease_tests.rs"))),
        "primitive_only":true,"private_state_parsed":false,"native_authority":false,
        "signing_authority":false,"payment_qualified":false,"mainnet":false});
    meta(&root, "mesh-wrapper-scope.json", &scope).unwrap();
    eprintln!("mesh_wrapper_scope={scope}");
    let mesh = directory(&root.join("mesh")).unwrap();
    let observation = directory(&root.join("observation")).unwrap();
    let instance = random().unwrap();
    let node_id = random().unwrap();
    // This binding labels a lock primitive, not an authenticated node identity.
    let guard = start(
        true,
        &observation,
        &instance,
        Hash([1; 32]),
        Hash([2; 32]),
        &node_id,
    )
    .unwrap()
    .unwrap();
    let sink = guard.sink().unwrap();
    let config = json!({"state":mesh});
    {
        let _disabled = mesh_role(None, &config, "main", None);
        let _operation = mesh_operation("capture");
        let lease = Lease::acquire(&mesh, "Mesh").unwrap();
        drop(lease);
    }
    assert_eq!(sink.shared.next_attempt.load(Ordering::Acquire), 0);
    assert_eq!(sink.shared.active.load(Ordering::Acquire), 0);
    assert_eq!(sink.shared.loss.load(Ordering::Acquire), 0);
    assert_eq!(sink.shared.errors.load(Ordering::Acquire), 0);
    let busy_error;
    {
        let _role = mesh_role(Some(&sink), &config, "main", None);
        let _operation = mesh_operation("capture");
        let first = Lease::acquire(&mesh, "Mesh").unwrap();
        busy_error = match Lease::acquire(&mesh, "Mesh") {
            Ok(_) => panic!("second real same-path Mesh acquire unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(busy_error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK)));
        drop(first);
        let last = Lease::acquire(&mesh, "Mesh").unwrap();
        drop(last);
    }
    assert_eq!(sink.shared.next_attempt.load(Ordering::Acquire), 3);
    assert_eq!(sink.shared.active.load(Ordering::Acquire), 0);
    drop(sink);
    guard.finish(true).unwrap();
    inside(deadline);
    let scope_bytes = fs::read(observation.join(SCOPE)).unwrap();
    let events = fs::read(observation.join(EVENTS)).unwrap();
    let terminal: Value =
        serde_json::from_slice(&fs::read(observation.join(TERMINAL)).unwrap()).unwrap();
    assert!(events.ends_with(b"\n") && events.len() <= MAX_BYTES);
    let rows = events
        .split(|b| *b == b'\n')
        .filter(|r| !r.is_empty())
        .map(|r| serde_json::from_slice::<Value>(r).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 14);
    assert_eq!(terminal["success"], true);
    assert_eq!(terminal["requested_success"], true);
    for key in [
        "errors",
        "loss",
        "incomplete_attempts",
        "active_attempts",
        "remaining_sink_handles",
    ] {
        assert_eq!(terminal[key], 0);
    }
    assert_eq!(
        terminal["scope_sha256"],
        hex::encode(Sha256::digest(&scope_bytes))
    );
    assert_eq!(
        terminal["events_sha256"],
        hex::encode(Sha256::digest(&events))
    );
    assert_eq!(terminal["complete_rows_sha256"], terminal["events_sha256"]);
    assert_eq!(terminal["rows"], rows.len());
    assert_eq!(terminal["events_bytes"], events.len());
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["written_sequence"], index + 1);
        assert_eq!(row["lane"], "mesh-lease");
        assert_eq!(row["diagnostic_only"], true);
        assert_eq!(row["native_authority"], false);
        let detail = row["detail"].as_object().unwrap();
        for forbidden in ["token", "path", "root", "config", "key", "seed", "fd"] {
            assert!(!detail.contains_key(forbidden));
        }
    }
    let mut acquisition = Vec::new();
    let mut release = Vec::new();
    for id in 1..=3 {
        let attempt = rows
            .iter()
            .filter(|r| r["attempt_id"] == id)
            .collect::<Vec<_>>();
        assert_eq!(attempt[0]["phase"], "attempt-started");
        assert_eq!(
            attempt[0]["detail"],
            json!({"role":"main","operation":"capture",
            "parent_attempt_id":null,"main_turn":null})
        );
        assert_eq!(attempt[1]["phase"], "mesh-acquire-call");
        assert_eq!(attempt[2]["phase"], "mesh-acquire-result");
        let begin = attempt[1]["detail"]["call_before"].as_f64().unwrap();
        let end = attempt[2]["detail"]["returned_after"].as_f64().unwrap();
        assert!(begin.is_finite() && end.is_finite() && started <= begin && begin <= end);
        assert_eq!(attempt[2]["detail"]["call_before"].as_f64(), Some(begin));
        acquisition.push((begin, end));
        if id == 2 {
            assert_eq!(attempt.len(), 4);
            assert_eq!(attempt[2]["detail"]["result"], "would-block");
            assert_eq!(attempt[3]["phase"], "attempt-completed");
            assert_eq!(attempt[3]["detail"]["result"], "error");
        } else {
            assert_eq!(attempt.len(), 5);
            assert_eq!(attempt[2]["detail"]["result"], "acquired");
            assert_eq!(attempt[3]["phase"], "mesh-release-result");
            assert_eq!(attempt[3]["detail"]["result"], "release-ok");
            let r0 = attempt[3]["detail"]["call_before"].as_f64().unwrap();
            let r1 = attempt[3]["detail"]["returned_after"].as_f64().unwrap();
            assert!(end <= r0 && r0 <= r1 && r1 < deadline);
            release.push((r0, r1));
            assert_eq!(attempt[4]["phase"], "attempt-completed");
            assert_eq!(attempt[4]["detail"]["result"], "ok");
        }
    }
    // Whole failed API call bracket is inside certain-held lower interval.
    assert!(acquisition[0].1 <= acquisition[1].0 && acquisition[1].1 <= release[0].0);
    assert!(release[0].1 <= acquisition[2].0);
    inside(deadline);
    let ended = now();
    let result = json!({"format":FORMAT,"root":root,"pid":std::process::id(),
        "started":started,"ended":ended,"deadline":deadline,"elapsed_seconds":ended-started,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "test_source_sha256":scope["test_source_sha256"],"passed":true,
        "disabled_no_telemetry":true,"real_busy_refused":true,"later_acquire_succeeded":true,
        "observer_rows":14,"observer_attempts":3,"held_interval_contains_failed_call":true,
        "no_sensitive_metadata":true,"all_producers_closed":true,"primitive_only":true,
        "native_authority":false,"signing_authority":false,"payment_qualified":false,"mainnet":false});
    meta(&root, "mesh-wrapper-result.json", &result).unwrap();
    eprintln!("mesh_wrapper_result={result}");
    inside(deadline);
}

#[test]
#[ignore = "one fresh enabled observer refusal with real lock results preserved; no OS fault"]
fn passive_mesh_observer_failure_preserves_real_lock_and_refuses_footer() {
    assert_eq!(std::env::var("RLD_MESH_WRAPPER_UNIT").as_deref(), Ok("1"));
    let started = now();
    let deadline = started + 10.0;
    let root = directory(
        &fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-passive-mesh-wrapper-failure-{}",
                random().unwrap()
            )),
    )
    .unwrap();
    let scope = json!({"format":FORMAT,"case":"diagnostic-failure","root":root,
        "pid":std::process::id(),"started":started,"deadline":deadline,
        "scope_seconds":10,"external_stop_seconds":15,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "test_source_sha256":hex::encode(Sha256::digest(include_bytes!("service_mesh_lease_tests.rs"))),
        "primitive_only":true,"private_state_parsed":false,"native_authority":false,
        "signing_authority":false,"payment_qualified":false,"mainnet":false});
    meta(&root, "mesh-wrapper-scope.json", &scope).unwrap();
    eprintln!("mesh_wrapper_scope={scope}");
    let mesh = directory(&root.join("mesh")).unwrap();
    let observation = directory(&root.join("observation")).unwrap();
    let guard = start(
        true,
        &observation,
        &random().unwrap(),
        Hash([1; 32]),
        Hash([2; 32]),
        &random().unwrap(),
    )
    .unwrap()
    .unwrap();
    let sink = guard.sink().unwrap();
    let config = json!({"state":mesh});
    {
        let _role = mesh_role(Some(&sink), &config, "main", None);
        let _operation = mesh_operation("capture");
        // The observer cannot borrow context, but actual OS locks still behave.
        super::super::MESH_ROLE_CONTEXT.with(|slot| {
            let _borrow = slot.context.borrow_mut();
            let held = Lease::acquire(&mesh, "Mesh").unwrap();
            let error = match Lease::acquire(&mesh, "Mesh") {
                Ok(_) => panic!("real held Mesh unexpectedly admitted a second owner"),
                Err(error) => error,
            };
            assert!(error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EWOULDBLOCK)));
            drop(held);
        });
    }
    assert!(sink.shared.errors.load(Ordering::Acquire) > 0);
    {
        let _role = mesh_role(Some(&sink), &config, "main", None);
        let _operation = mesh_operation("capture");
        let lease = Lease::acquire(&mesh, "Mesh").unwrap();
        let attempt = lease
            .observation
            .as_ref()
            .unwrap()
            .attempt
            .as_ref()
            .unwrap();
        // Pure diagnostic input validation; global/Native clock and OS are untouched.
        assert!(super::super::mesh_clock_sample(attempt, None).is_none());
        assert!(super::super::mesh_clock_sample(attempt, Some(f64::NAN)).is_none());
        drop(lease);
    }
    assert_eq!(sink.shared.active.load(Ordering::Acquire), 0);
    drop(sink);
    assert_eq!(
        guard.finish(true).unwrap_err(),
        "Carriage incomplete observation cannot seal true"
    );
    inside(deadline);
    let terminal: Value =
        serde_json::from_slice(&fs::read(observation.join(TERMINAL)).unwrap()).unwrap();
    assert_eq!(terminal["success"], false);
    assert_eq!(terminal["requested_success"], true);
    assert!(terminal["errors"].as_u64().unwrap() > 0);
    assert_eq!(terminal["active_attempts"], 0);
    assert_eq!(terminal["remaining_sink_handles"], 0);
    assert_eq!(terminal["loss"], 0);
    let raw = fs::read(observation.join(EVENTS)).unwrap();
    assert!(raw.ends_with(b"\n"));
    assert_eq!(terminal["events_sha256"], hex::encode(Sha256::digest(&raw)));
    let ended = now();
    inside(deadline);
    let result = json!({"format":FORMAT,"case":"diagnostic-failure","root":root,"pid":std::process::id(),
        "started":started,"ended":ended,"deadline":deadline,"elapsed_seconds":ended-started,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),"test_source_sha256":scope["test_source_sha256"],
        "passed":true,"enabled_borrow_failure_reported":true,"clock_failure_reported":true,
        "real_lock_success_preserved":true,"actual_busy_preserved":true,"later_acquire_succeeded":true,
        "expected_footer_success":false,"all_producers_closed":true,"primitive_only":true,
        "native_authority":false,"signing_authority":false,"payment_qualified":false,"mainnet":false});
    meta(&root, "mesh-wrapper-result.json", &result).unwrap();
    eprintln!("mesh_wrapper_result={result}");
    inside(deadline);
}
