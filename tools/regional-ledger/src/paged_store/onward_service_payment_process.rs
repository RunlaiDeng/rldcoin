//! Test-only ordinary CLI process ownership; no frame delivery or scheduler hook.
use super::*;
use std::process::Child;

fn output(path: &Path) -> fs::File {
    crate::keystore::private_create(path, b"").unwrap();
    fs::OpenOptions::new().write(true).open(path).unwrap()
}
struct ChildService {
    child: Child,
    stdout: PathBuf,
    joined: bool,
    ready: bool,
}
pub(super) struct Services {
    children: Vec<ChildService>,
    cleanup_deadline: f64,
}
impl Services {
    pub(super) fn new(cleanup_deadline: f64) -> Self {
        Self {
            children: vec![],
            cleanup_deadline,
        }
    }
    pub(super) fn launch(&mut self, root: &Path, setup: &Setup, addresses: &[String]) {
        for (i, address) in addresses.iter().enumerate() {
            within(setup.deadline);
            let ledger = if i == 0 {
                root.join("intermediate")
            } else {
                ledger_path(root, i - 1)
            };
            let stdout = root.join(format!("service-{i}.stdout"));
            let stderr = root.join(format!("service-{i}.stderr"));
            let mut command = Process::new(&setup.cli);
            command.args([
                "--dir",
                ledger.to_str().unwrap(),
                "--authority",
                &public(1),
                "--currency",
                &setup.currency.to_hex(),
                "--mesh-config",
                root.join(format!("payment-transport-{i}.json"))
                    .to_str()
                    .unwrap(),
                "--mesh-listen",
                address,
                "--interval",
                "0.1",
            ]);
            if i > 0 {
                command.args([
                    "--bft-config",
                    root.join(format!("payment-runtime-{}.json", i - 1))
                        .to_str()
                        .unwrap(),
                ]);
            }
            let child = command
                .stdout(Stdio::from(output(&stdout)))
                .stderr(Stdio::from(output(&stderr)))
                .spawn()
                .unwrap();
            let pid = child.id();
            self.children.push(ChildService {
                child,
                stdout: stdout.clone(),
                joined: false,
                ready: false,
            });
            new_json(
                &root.join(format!("service-{i}-launch.json")),
                &json!({
                "index":i,"pid":pid,"launched_at":now(),"ledger":ledger,
                "listen":address,"stdout":stdout,"stderr":stderr,
                "cli_sha256":setup.cli_sha256,"ordinary_no_action_startup":true}),
            );
        }
        // All five ordinary processes have been spawned before any readiness wait.
        while self.children.iter().any(|c| !c.ready) {
            within(setup.deadline);
            self.running();
            for (i, child) in self.children.iter_mut().enumerate() {
                if child.ready {
                    continue;
                }
                let raw = fs::read(&child.stdout).unwrap();
                assert!(raw.len() <= 64 * 1024);
                if let Some(end) = raw.iter().position(|b| *b == b'\n') {
                    let value: Value = serde_json::from_slice(&raw[..end]).unwrap();
                    assert_eq!(value["listen"], addresses[i]);
                    assert_eq!(value["tls"]["fingerprint"], setup.tls[i]["fingerprint"]);
                    child.ready = true;
                }
            }
            if self.children.iter().any(|c| !c.ready) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    pub(super) fn running(&mut self) {
        for (i, c) in self.children.iter_mut().enumerate() {
            if let Some(status) = c.child.try_wait().unwrap() {
                c.joined = true;
                panic!("ordinary Service {i} exited before requested stop: {status}");
            }
        }
    }
    pub(super) fn stop(&mut self, root: &Path, deadline: f64) -> Vec<Value> {
        within(deadline);
        self.running();
        let requested_at = now();
        for c in &self.children {
            assert_eq!(
                unsafe { libc::kill(c.child.id() as libc::pid_t, libc::SIGTERM) },
                0
            );
        }
        let mut results = vec![Value::Null; self.children.len()];
        while self.children.iter().any(|c| !c.joined) {
            within(deadline);
            for (i, c) in self.children.iter_mut().enumerate() {
                if c.joined {
                    continue;
                }
                if let Some(status) = c.child.try_wait().unwrap() {
                    c.joined = true;
                    results[i] = json!({"index":i,"pid":c.child.id(),"stop_requested_at":requested_at,
                        "joined_at":now(),"success":status.success(),"status":status.to_string()});
                    new_json(&root.join(format!("service-{i}-exit.json")), &results[i]);
                    assert!(
                        status.success(),
                        "ordinary Service {i} did not stop normally: {status}"
                    );
                }
            }
            if self.children.iter().any(|c| !c.joined) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        within(deadline);
        results
    }
}
impl Drop for Services {
    fn drop(&mut self) {
        // Failure only: fan out first, then use the single original stop-only boundary.
        for c in self.children.iter_mut().filter(|c| !c.joined) {
            unsafe {
                libc::kill(c.child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
        while self.children.iter().any(|c| !c.joined)
            && crate::bft_tick_schedule::monotonic().is_ok_and(|at| at < self.cleanup_deadline)
        {
            for c in self.children.iter_mut().filter(|c| !c.joined) {
                if c.child.try_wait().ok().flatten().is_some() {
                    c.joined = true;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for c in self.children.iter_mut().filter(|c| !c.joined) {
            let _ = c.child.kill();
        }
        for c in self.children.iter_mut().filter(|c| !c.joined) {
            let _ = c.child.wait();
            c.joined = true;
        }
    }
}

struct ColdChild {
    process: Child,
    joined: bool,
}
impl Drop for ColdChild {
    fn drop(&mut self) {
        if !self.joined {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }
}

pub(super) fn cold_join(root: &Path, setup: &Setup) {
    within(setup.deadline);
    let out = root.join("payment-cold.stdout");
    let err = root.join("payment-cold.stderr");
    let stdout = output(&out);
    let stderr = output(&err);
    let mut before = inventory(root);
    // Harness preamble/result and the final cold marker are expected only in these two files.
    before.remove(&out);
    before.remove(&err);
    assert_eq!(std::env::current_exe().unwrap(), setup.test_binary);
    let process = Process::new(&setup.test_binary)
        .args([
            "--exact",
            TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, root)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    let mut child = ColdChild {
        process,
        joined: false,
    };
    loop {
        if let Some(status) = child.process.try_wait().unwrap() {
            child.joined = true;
            assert!(
                status.success(),
                "fresh child refused; retained {}",
                err.display()
            );
            within(setup.deadline);
            let raw = fs::read_to_string(&err).unwrap();
            let prefix = "onward_service_payment_cold_result=";
            let rows = raw
                .lines()
                .filter_map(|s| s.strip_prefix(prefix))
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 1);
            assert!(raw.ends_with('\n'));
            let report: Value = serde_json::from_str(rows[0]).unwrap();
            assert_eq!(report["parent_pid"], setup.parent_pid);
            assert_eq!(report["pid"], child.process.id());
            assert_eq!(report["started"], setup.started);
            assert_eq!(report["deadline"], setup.deadline);
            assert_eq!(report["mode"], "two-original-owner-payments");
            assert_eq!(
                report["test_binary_sha256"],
                serde_json::to_value(setup.test_binary_sha256).unwrap()
            );
            assert_eq!(report["passed"], true);
            assert_eq!(report["four_native_runtime_cold"], true);
            assert_eq!(report["both_original_owners_cold"], true);
            assert_eq!(report["inventory_unchanged"], true);
            let mut after = inventory(root);
            after.remove(&out);
            after.remove(&err);
            assert_eq!(
                after, before,
                "parent cold-child readback changed non-output fixture files"
            );
            within(setup.deadline);
            return;
        }
        if now() >= setup.deadline {
            panic!("original120 exhausted during complete fresh child cold checks");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
