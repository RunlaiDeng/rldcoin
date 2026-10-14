//! A separate bounded observation of ordinary carriage, never a payment pass.
use super::*;

struct Failure {
    root: PathBuf,
    started: f64,
    completed: bool,
}
impl Drop for Failure {
    fn drop(&mut self) {
        if !self.completed {
            let report = json!({"root":self.root,"started":self.started,"at":now(),
                "passed":false,"diagnostic_only":true,"owner_requests":0,
                "payment_qualification":false,"scope_seconds":30,"stop_upper_bound_seconds":35});
            // This precedes potentially slow emergency Service cleanup.
            new_json(&self.root.join("carriage-boundary-failure.json"), &report);
            eprintln!("onward_service_carriage_boundary_failure={report}");
        }
    }
}

#[test]
#[ignore = "one fresh five-Service ordinary carriage observation; original30 including setup and normal stop, emergency35"]
fn ordinary_onward_service_c1_carriage_boundaries() {
    assert_eq!(
        std::env::var("RLD_SERVICE_NATIVE_OBSERVATION").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("RLD_SERVICE_CARRIAGE_OBSERVATION").as_deref(),
        Ok("1")
    );
    let started = now();
    let deadline = started + 30.0;
    let measure_until = started + 24.0;
    let (root, setup, sockets, addresses) = setup(started, deadline);
    let mut services = processes::Services::new(started + 35.0);
    let mut failure = Failure {
        root: root.clone(),
        started,
        completed: false,
    };
    eprintln!(
        "onward_service_carriage_boundary_scope={}",
        json!({
        "root":root,"started":started,"deadline":deadline,"measure_until":measure_until,
        "parent_pid":std::process::id(),"test_binary_sha256":setup.test_binary_sha256,
        "cli_sha256":setup.cli_sha256,"passed":false,"diagnostic_only":true,
        "original_all_configured_neighbors":true,"owner_requests":0})
    );
    drop(sockets);
    services.launch(&root, &setup, &addresses);
    let mut last_heads = [Hash::ZERO; 4];
    let mut unknown = [0u64; 4];
    let mut native_observations = Vec::new();
    // Preserve the original four-Store live polling pattern and complete
    // Native replay; no controller signature, frame, cursor or C block.
    while now() < measure_until {
        within(deadline);
        services.running();
        for actor in 0..4 {
            if now() >= measure_until {
                break;
            }
            services.running();
            let dispatched_at = now();
            let node = match Store::open_inspection(
                &ledger_path(&root, actor),
                &public(1),
                setup.currency,
            ) {
                Ok(node) => node,
                Err(error) if error == std::fs::TryLockError::WouldBlock.to_string() => {
                    unknown[actor] += 1;
                    continue;
                }
                Err(error) => {
                    panic!("ordinary Native diagnostic refused for actor {actor}: {error}")
                }
            };
            let returned_at = now();
            node.require_onward_network_state().unwrap();
            assert!(node.chain.height() <= STOP_HEIGHT);
            let head = node.storage_head().unwrap();
            if last_heads[actor] != head {
                assert!(native_observations.len() < 512);
                native_observations.push(json!({"actor":actor,"dispatched_at":dispatched_at,
                    "returned_at":returned_at,"height":node.chain.height(),"head":head,
                    "finality":node.chain.finalized,"unknown_lock_observations":unknown[actor]}));
                last_heads[actor] = head;
            }
            drop(node);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let normal_stops = services.stop(&root, deadline);
    drop(services);
    let mut terminal_native = Vec::new();
    for actor in 0..4 {
        within(deadline);
        let node =
            Store::open_inspection(&ledger_path(&root, actor), &public(1), setup.currency).unwrap();
        node.require_onward_network_state().unwrap();
        terminal_native.push(json!({"actor":actor,"height":node.chain.height(),
            "head":node.storage_head().unwrap(),"finality":node.chain.finalized}));
    }
    // These are genuine writer closures after the CLI's actual worker joins.
    // The external source-bound parser must still validate complete bytes and
    // every attempt; a Boolean never supplies Native or custody authority.
    let mut observers = Vec::new();
    for actor in 0..5 {
        within(deadline);
        let state = root.join(format!("payment-transport-state-{actor}"));
        let native: Value =
            serde_json::from_slice(&fs::read(state.join("native-schedule-terminal.json")).unwrap())
                .unwrap();
        let carriage: Value = serde_json::from_slice(
            &fs::read(state.join("carriage-boundary-terminal.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(native["success"], true);
        assert_eq!(carriage["success"], true);
        observers.push(json!({"actor":actor,"native":native,"carriage":carriage}));
    }
    within(deadline);
    let report = json!({"root":root,"started":started,"deadline":deadline,"ended":now(),
        "measure_until":measure_until,"passed":true,"diagnostic_only":true,
        "parent_pid":std::process::id(),"test_binary_sha256":setup.test_binary_sha256,
        "cli_sha256":setup.cli_sha256,"native_observations":native_observations,
        "terminal_native":terminal_native,"normal_stops":normal_stops,
        "observers":observers,"unknown_lock_observations":unknown,
        "owner_requests":0,"controller_votes_or_frames_or_blocks":false,
        "whole_payment_pass":false,"normal_latency_cohort_qualified":false,
        "independent_qualification":false,"mainnet":false});
    new_json(&root.join("carriage-boundary-result.json"), &report);
    within(deadline);
    failure.completed = true;
    eprintln!("onward_service_carriage_boundary_result={report}");
}
