//! Separate bounded proving lanes. Witness replay never holds the live node
//! mutex; immutable observations grant no new ledger or signing authority.
use super::*;
use crate::{proving::ProofContext, store::sync_dir};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use std::{collections::BTreeMap, fs::File, time::Instant};
use tokio::{sync::Semaphore, task::JoinSet};

const MAX_FILES: u64 = 16_384;
const LOG_BYTES: u64 = 128 * 1024;
const ATTEMPT_BYTES: u64 = rld_protocol::MAX_RECEIPT as u64 + 128 + LOG_BYTES + 1024;
const ATTEMPT_FILES: u64 = 3;

pub(super) fn default_bytes() -> u64 {
    1024 * 1024 * 1024
}
pub(super) fn default_concurrency() -> u8 {
    3
}
pub(super) fn default_timeout() -> u64 {
    3600
}

/// This workspace owns only proving inputs, receipts and bounded diagnostics.
/// Its currency/domain/genesis binding prevents accidental reuse across nodes.
pub(super) struct Workspace {
    root: PathBuf,
    capacity: u64,
    active: Mutex<BTreeSet<Id>>,
    _lock: File,
}
impl Workspace {
    pub(super) fn open(root: &Path, capacity: u64, node: &Node) -> Result<Arc<Self>> {
        ensure!(
            (ATTEMPT_BYTES..=1024 * 1024 * 1024 * 1024).contains(&capacity),
            "proof workspace byte budget"
        );
        ensure!(!root.is_symlink(), "proof workspace root symlink");
        let fresh = !root.exists();
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fresh {
                fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(root.join("LOCK"))?;
        lock.try_lock_exclusive()
            .context("proof workspace already in use")?;
        let binding = encode(&(
            "RLD-PROOF-WORKSPACE-1",
            node.core.state.currency,
            node.core.state.domain,
            rld_protocol::state::genesis_id(node.core.state.currency, &node.core.initial.genesis),
        ));
        let path = root.join("WORKSPACE.cbor");
        if path.exists() {
            ensure!(
                read_bounded(&path, 1024)? == binding,
                "proof workspace currency/domain/genesis mismatch"
            );
        } else {
            ensure!(
                fs::read_dir(root)?.all(|entry| entry.is_ok_and(|e| e.file_name() == "LOCK")),
                "unbound legacy proof workspace: retain it and use a fresh directory"
            );
            private_create(&path, &binding)?;
            sync_dir(root)?;
        }
        let workspace = Arc::new(Self {
            root: root.into(),
            capacity,
            active: Mutex::new(BTreeSet::new()),
            _lock: lock,
        });
        // Capacity exhaustion pauses new proving work, not the ledger or an
        // owner's independent cancellation path. Each actual write/attempt
        // still checks retained bytes plus all concurrent reservations.
        Ok(workspace)
    }
    fn inventory(&self) -> Result<(u64, u64)> {
        let (mut bytes, mut files) = (0u64, 0u64);
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "unexpected proof workspace entry; preserve unchanged"
            );
            files = files.checked_add(1).context("proof file count overflow")?;
            bytes = bytes
                .checked_add(entry.metadata()?.len())
                .context("proof byte count overflow")?;
            ensure!(
                files <= MAX_FILES && bytes <= self.capacity,
                "proof workspace capacity exhausted; retain all evidence"
            );
        }
        Ok((bytes, files))
    }
    // Active reservations are conservatively counted even when their partial
    // files already appear in inventory. No work is admitted on promised space.
    fn admit(&self, bytes: u64, files: u64, active: usize) -> Result<()> {
        let (used, count) = self.inventory()?;
        ensure!(
            used.checked_add(bytes)
                .and_then(|n| n.checked_add(active as u64 * ATTEMPT_BYTES))
                .is_some_and(|n| n <= self.capacity)
                && count
                    .checked_add(files)
                    .and_then(|n| n.checked_add(active as u64 * ATTEMPT_FILES))
                    .is_some_and(|n| n <= MAX_FILES),
            "proof workspace configured byte/file budget exhausted; existing obligations retained"
        );
        Ok(())
    }
    fn input(&self, job: &Job, bytes: &[u8]) -> Result<PathBuf> {
        let active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("proof workspace unavailable"))?;
        let path = self
            .root
            .join(format!("{}-{}.input.cbor", job.kind(), job.id));
        if path.exists() {
            ensure!(
                read_bounded(&path, crate::store::MAX_RECORD)? == bytes,
                "changed retained proof input"
            );
            File::open(&path)?.sync_all()?;
        } else {
            self.admit(bytes.len() as u64, 1, active.len())?;
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let pending = self.root.join(format!(
                "{}-{}.input-attempt-{}.cbor",
                job.kind(),
                job.id,
                Id(nonce)
            ));
            private_create(&pending, bytes)?;
            sync_dir(&self.root)?;
            // A partial write stays under its unique attempt name. It never
            // occupies the canonical exact-input path or blocks safe retry.
            fs::rename(pending, &path)?;
        }
        sync_dir(&self.root)?;
        Ok(path)
    }
    fn begin(self: &Arc<Self>, job: Id) -> Result<Attempt> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| anyhow::anyhow!("proof workspace unavailable"))?;
        ensure!(
            !active.contains(&job),
            "same exact proof job is already running"
        );
        self.admit(ATTEMPT_BYTES, ATTEMPT_FILES, active.len())?;
        active.insert(job);
        Ok(Attempt {
            workspace: self.clone(),
            job,
        })
    }
}
struct Attempt {
    workspace: Arc<Workspace>,
    job: Id,
}

/// The actual prover can start subprocesses. Canceling one lane must terminate
/// its isolated process group as well as the direct child. No unrelated process
/// joins this newly created group. Signal delivery is not a custody guarantee.
#[cfg(unix)]
struct ProcessGroup(u32);
#[cfg(unix)]
impl ProcessGroup {
    fn terminate(&mut self) {
        if self.0 != 0 {
            unsafe {
                libc::kill(-(self.0 as libc::pid_t), libc::SIGKILL);
            }
            self.0 = 0;
        }
    }
}
#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // The child sets its own process-group ID to its PID before exec.
        // A negative PID targets that group, including surviving descendants.
        self.terminate();
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if let Ok(mut active) = self.workspace.active.lock() {
            active.remove(&self.job);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Native(u64),
    Controller(Id),
}
#[derive(Clone, Copy)]
enum Lane {
    Birth,
    Controller,
    Native,
}
struct Snapshot {
    view: ProofContext,
    terminal: BTreeSet<Id>,
    queued: BTreeSet<Id>,
}
impl Snapshot {
    fn targets(&self, lane: Lane) -> Result<BTreeSet<Target>> {
        let closed: BTreeSet<_> = self
            .view
            .state
            .resolutions
            .iter()
            .map(|r| r.object)
            .chain(self.terminal.iter().copied())
            .collect();
        let mut targets = BTreeSet::new();
        match lane {
            Lane::Native => {
                let n = self.view.state.sequence;
                if n > 0 && !self.view.proofs.contains(n)? {
                    targets.insert(Target::Native(n));
                }
            }
            Lane::Birth | Lane::Controller => {
                // Read only relevant birth heights; do not collect every historical
                // certificate or silently turn an I/O failure into proof absence.
                let mut ready = BTreeMap::new();
                for birth in self.view.state.births.iter() {
                    if closed.contains(&birth.controller) {
                        continue;
                    }
                    if matches!(lane, Lane::Controller) && self.queued.contains(&birth.controller) {
                        continue;
                    }
                    let available = if let Some(value) = ready.get(&birth.sequence) {
                        *value
                    } else {
                        let value = self.view.proofs.contains(birth.sequence)?;
                        ready.insert(birth.sequence, value);
                        value
                    };
                    match lane {
                        Lane::Birth if !available => {
                            targets.insert(Target::Native(birth.sequence));
                        }
                        Lane::Controller if available => {
                            targets.insert(Target::Controller(birth.controller));
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(targets)
    }
    fn prepare(self, target: Target) -> Result<Job> {
        let currency = self.view.initial.currency.clone();
        let (bytes, product, image, journal) = match target {
            Target::Native(mut sequence) => {
                let base = self
                    .view
                    .proofs
                    .before(sequence)?
                    .map_or(0, |p| p.header.sequence);
                sequence = sequence.min(
                    base.checked_add(4096)
                        .context("proof sequence exhaustion")?,
                );
                let input = self.view.native_input(sequence)?;
                let record = self.view.history.at(sequence)?.context("proof history")?;
                let certificate = Certified {
                    header: record.header.clone(),
                    qc: record.qc.clone(),
                    configuration: record.configuration.clone(),
                    receipt: Blob(vec![]),
                };
                (
                    rld_protocol::codec::encode_bounded(&input, crate::store::MAX_RECORD)?,
                    Product::Native(certificate),
                    currency.proof.native_image,
                    proof::native_journal(&record.header),
                )
            }
            Target::Controller(id) => {
                let witness = self.view.controller_witness(id)?;
                let journal = proof::terminal_journal(&witness.terminal);
                let bytes = encode(&witness);
                let release = Release {
                    creation: witness.creation,
                    terminal: witness.terminal,
                    receipt: Blob(vec![]),
                    qc: Quorum { votes: vec![] },
                    covers: witness.covers,
                    material: witness.material,
                };
                (
                    bytes,
                    Product::Controller(release),
                    currency.proof.controller_image,
                    journal,
                )
            }
        };
        ensure!(
            bytes.len() <= crate::store::MAX_RECORD,
            "proof witness exceeds retained input bound"
        );
        Ok(Job {
            id: Id::digest(&bytes),
            bytes,
            product,
            currency,
            image,
            journal,
        })
    }
}
enum Product {
    Native(Certified),
    Controller(Release),
}
struct Job {
    id: Id,
    bytes: Vec<u8>,
    product: Product,
    currency: Currency,
    image: Id,
    journal: Vec<u8>,
}
impl Job {
    fn kind(&self) -> &'static str {
        match self.product {
            Product::Native(_) => "native",
            Product::Controller(_) => "controller",
        }
    }
    fn verify(&self, receipt: &Blob) -> Result<()> {
        proof::Verifier {
            currency: &self.currency,
        }
        .receipt(self.image, &self.journal, receipt)
    }
    fn publish(&self, receipt: Blob, node: &mut Node) -> Result<()> {
        match &self.product {
            Product::Native(certificate) => {
                let mut c = certificate.clone();
                c.receipt = receipt;
                node.certificate(c)
            }
            Product::Controller(release) => {
                let mut r = release.clone();
                r.receipt = receipt;
                node.queue_candidate(rld_protocol::consensus::Payload::Export(r))
            }
        }
    }
}

pub(super) async fn worker(
    shared: SharedState,
    exe: PathBuf,
    workspace: Arc<Workspace>,
    concurrency: u8,
    timeout: Duration,
) {
    let permits = Arc::new(Semaphore::new(concurrency as usize));
    let mut tasks = JoinSet::new();
    for lane in [Lane::Birth, Lane::Controller, Lane::Native] {
        tasks.spawn(run_lane(
            shared.clone(),
            exe.clone(),
            workspace.clone(),
            permits.clone(),
            lane,
            timeout,
        ));
    }
    // Dropping this supervisor aborts all lanes. Each prover child uses
    // kill_on_drop; abandoned read-only spawn_blocking work cannot sign.
    while let Some(result) = tasks.join_next().await {
        let message = match result {
            Ok(()) => "proof lane stopped unexpectedly".into(),
            Err(e) => format!("proof lane stopped: {e}"),
        };
        report(shared.clone(), message).await;
    }
}
async fn observe(shared: SharedState) -> Result<Snapshot> {
    tokio::task::spawn_blocking(move || {
        let s = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?;
        Ok(Snapshot {
            view: s.node.core.proof_context(),
            terminal: s
                .node
                .core
                .terminals
                .iter()
                .filter_map(|r| match &r.payload {
                    rld_protocol::consensus::Payload::Export(r) => Some(r.creation.controller.id),
                    rld_protocol::consensus::Payload::Cancel(c) => Some(c.controller),
                    rld_protocol::consensus::Payload::Native { .. } => None,
                })
                .collect(),
            queued: s
                .node
                .core
                .candidates
                .iter()
                .filter_map(|p| match p {
                    rld_protocol::consensus::Payload::Export(r) => Some(r.creation.controller.id),
                    rld_protocol::consensus::Payload::Cancel(c) => Some(c.controller),
                    _ => None,
                })
                .collect(),
        })
    })
    .await?
}
async fn report(shared: SharedState, message: String) {
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(mut s) = shared.lock() {
            s.node.last_error = Some(message);
        }
    })
    .await;
}
async fn run_lane(
    shared: SharedState,
    exe: PathBuf,
    workspace: Arc<Workspace>,
    permits: Arc<Semaphore>,
    lane: Lane,
    timeout: Duration,
) {
    let mut cursor = None;
    let mut failures: BTreeMap<Target, (u32, Instant)> = BTreeMap::new();
    loop {
        let result = async {
            let _permit = permits
                .acquire()
                .await
                .context("proof scheduling stopped")?;
            let snapshot = observe(shared.clone()).await?;
            let (snapshot, targets) = tokio::task::spawn_blocking(move || -> Result<_> {
                let targets = snapshot.targets(lane)?;
                Ok((snapshot, targets))
            })
            .await??;
            failures.retain(|target, _| targets.contains(target));
            let eligible = |t: &&Target| {
                failures
                    .get(t)
                    .is_none_or(|(_, when)| Instant::now() >= *when)
            };
            let target = targets
                .iter()
                .filter(eligible)
                .find(|t| cursor.is_none_or(|c| **t > c))
                .or_else(|| targets.iter().filter(eligible).next())
                .copied();
            let Some(target) = target else {
                return Ok::<_, anyhow::Error>(());
            };
            cursor = Some(target);
            let outcome = async {
                let job =
                    Arc::new(tokio::task::spawn_blocking(move || snapshot.prepare(target)).await??);
                let receipt = execute(job.clone(), &exe, workspace.clone(), timeout)
                    .await
                    .with_context(|| format!("{} proof job {}", job.kind(), job.id))?;
                let live = shared.clone();
                tokio::task::spawn_blocking(move || {
                    let mut s = live
                        .lock()
                        .map_err(|_| anyhow::anyhow!("node unavailable"))?;
                    job.publish(receipt, &mut s.node)
                })
                .await??;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if outcome.is_ok() {
                failures.remove(&target);
            } else {
                let tries = failures
                    .get(&target)
                    .map_or(1, |(n, _)| n.saturating_add(1));
                let delay = Duration::from_secs((1u64 << tries.min(8)).min(300));
                failures.insert(target, (tries, Instant::now() + delay));
            }
            outcome
        }
        .await;
        if let Err(e) = result {
            report(shared.clone(), format!("proof service: {e}")).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn verify(job: Arc<Job>, receipt: Blob) -> Result<Blob> {
    tokio::task::spawn_blocking(move || {
        job.verify(&receipt)?;
        Ok(receipt)
    })
    .await?
}
async fn execute(
    job: Arc<Job>,
    exe: &Path,
    workspace: Arc<Workspace>,
    timeout: Duration,
) -> Result<Blob> {
    let w = workspace.clone();
    let j = job.clone();
    let input = tokio::task::spawn_blocking(move || w.input(&j, &j.bytes)).await??;
    let complete = workspace
        .root
        .join(format!("{}-{}.receipt.cbor", job.kind(), job.id));
    if complete.exists() {
        let receipt = decode(
            &read_bounded(&complete, rld_protocol::MAX_RECEIPT + 128)?,
            rld_protocol::MAX_RECEIPT + 128,
        )?;
        return verify(job, receipt).await;
    }
    let _attempt = workspace.begin(job.id)?;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let stem = format!("{}-{}-attempt-{}", job.kind(), job.id, Id(nonce));
    let output = workspace.root.join(format!("{stem}.output.cbor"));
    private_create(
        &workspace.root.join(format!("{stem}.cbor")),
        &encode(&(job.id, job.image, Id::digest(&job.journal))),
    )?;
    sync_dir(&workspace.root)?;
    let mut command = tokio::process::Command::new(exe);
    command
        .arg(job.kind())
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .env_remove("RISC0_DEV_MODE")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    let mut process = command.spawn()?;
    #[cfg(unix)]
    let mut process_group = ProcessGroup(process.id().context("prover process identity")?);
    async fn bounded_log(mut input: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut buffer = [0u8; 8192];
        let mut kept = Vec::new();
        loop {
            let n = input.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            let take = n.min((LOG_BYTES as usize / 2).saturating_sub(kept.len()));
            kept.extend_from_slice(&buffer[..take]);
        }
        Ok(kept)
    }
    let stdout = process.stdout.take().context("prover stdout")?;
    let stderr = process.stderr.take().context("prover stderr")?;
    let observed = tokio::time::timeout(timeout, async {
        tokio::join!(process.wait(), bounded_log(stdout), bounded_log(stderr))
    })
    .await;
    let (status, out, err) = match observed {
        Ok(result) => result,
        Err(_) => {
            #[cfg(unix)]
            process_group.terminate();
            let kill_request = process.start_kill();
            let diagnostic = private_create(&workspace.root.join(format!("{stem}.log")),
                format!("prover attempt exceeded {} seconds; requested termination; monetary obligations unchanged\n", timeout.as_secs()).as_bytes())
                .and_then(|_| sync_dir(&workspace.root));
            // Reap the actual direct child before admitting a replacement.
            // A wait observation alone never establishes process completion.
            let reaped = process.wait().await;
            diagnostic?;
            reaped?;
            kill_request?;
            anyhow::bail!("proof attempt timed out; input and partial attempt retained: {stem}");
        }
    };
    let (status, mut out, err) = (status?, out?, err?);
    out.extend_from_slice(&err);
    private_create(&workspace.root.join(format!("{stem}.log")), &out)?;
    sync_dir(&workspace.root)?;
    ensure!(
        status.success(),
        "prover failed; exact input and attempt diagnostics retained: {stem}"
    );
    let receipt = decode(
        &read_bounded(&output, rld_protocol::MAX_RECEIPT + 128)?,
        rld_protocol::MAX_RECEIPT + 128,
    )?;
    let receipt = verify(job, receipt).await?;
    File::open(&output)?.sync_all()?;
    // Only a fully verified receipt becomes the reusable canonical result.
    // Incomplete/invalid attempt files remain exact; retries use fresh names.
    // The exclusive workspace/job locks prevent another internal publisher.
    ensure!(
        !complete.exists(),
        "proof output publication raced; preserve both complete attempts"
    );
    fs::rename(output, complete)?;
    sync_dir(&workspace.root)?;
    Ok(receipt)
}
