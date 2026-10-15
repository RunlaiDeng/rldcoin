//! Default-disabled bounded metadata; producer diagnostics never affect carriage.
use crate::{require, wallet_client as files, Hash, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const FORMAT: &str = "RLD-SERVICE-CARRIAGE-OBSERVATION-V1";
const ENV: &str = "RLD_SERVICE_CARRIAGE_OBSERVATION";
const MAX_ROWS: usize = 16_384;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROW: usize = 16 * 1024;
const MAX_META: usize = 64 * 1024;
const CHANNEL: usize = 128;
const SCOPE: &str = "carriage-boundary-scope.json";
const EVENTS: &str = "carriage-boundary-events.jsonl";
const TERMINAL: &str = "carriage-boundary-terminal.json";

fn parse_enabled(value: Option<&OsStr>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(_) => Err("Carriage observation env must be absent or exactly 1".into()),
    }
}
pub(super) fn enabled_from_env() -> Result<bool> {
    parse_enabled(std::env::var_os(ENV).as_deref())
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_: .".contains(&b))
}
fn detail(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or("Carriage detail must be bounded metadata")?;
    require(object.len() <= 32, "Carriage metadata field bound")?;
    for (key, value) in object {
        require(
            !key.is_empty()
                && key.len() <= 64
                && key
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "Carriage metadata key bound",
        )?;
        require(
            !matches!(
                key.as_str(),
                "path"
                    | "root"
                    | "key"
                    | "private_key"
                    | "seed"
                    | "bundle"
                    | "payload"
                    | "config"
                    | "raw"
                    | "message"
                    | "error"
            ),
            "Carriage raw or sensitive metadata forbidden",
        )?;
        let valid = match value {
            Value::Null | Value::Bool(_) => true,
            Value::Number(number) => number.as_f64().is_some_and(f64::is_finite),
            Value::String(text) => identifier(text) || label(text),
            Value::Array(values) => {
                key.ends_with("_ids")
                    && values.len() <= 4
                    && values.iter().all(|v| v.as_str().is_some_and(identifier))
            }
            Value::Object(_) => false,
        };
        require(valid, "Carriage metadata scalar or four-ID bound")?;
    }
    Ok(())
}
fn bump(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1));
}
struct Shared {
    tx: SyncSender<Event>,
    created_at: f64,
    closed: AtomicBool,
    seal_requested: AtomicBool,
    requested_success: AtomicBool,
    next_attempt: AtomicU64,
    active: AtomicU64,
    handles: AtomicUsize,
    loss: AtomicU64,
    errors: AtomicU64,
    incomplete: AtomicU64,
}
impl Shared {
    fn add_handle(&self) {
        if self
            .handles
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .is_err()
        {
            bump(&self.errors);
        }
    }
    fn send(&self, event: Event) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => bump(&self.loss),
            Err(TrySendError::Disconnected(_)) => {
                bump(&self.loss);
                bump(&self.errors);
            }
        }
    }
}
struct Event {
    attempt: u64,
    sequence: u64,
    lane: &'static str,
    phase: String,
    observed_at: f64,
    detail: Value,
}
pub(super) struct Sink {
    shared: Arc<Shared>,
}
impl Clone for Sink {
    fn clone(&self) -> Self {
        self.shared.add_handle();
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.shared.handles.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Sink {
    pub(super) fn diagnostic_error(&self) {
        bump(&self.shared.errors);
    }
    /// Integration must check Option<Sink> before this call in disabled mode.
    pub(super) fn begin_attempt(
        &self,
        lane: &'static str,
        build: impl FnOnce() -> Result<Value>,
    ) -> Option<Attempt> {
        if self.shared.closed.load(Ordering::Acquire) {
            return None;
        }
        if !label(lane) {
            bump(&self.shared.errors);
            return None;
        }
        let id =
            match self
                .shared
                .next_attempt
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            {
                Ok(n) => n + 1,
                Err(_) => {
                    bump(&self.shared.errors);
                    return None;
                }
            };
        if self
            .shared
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .is_err()
        {
            bump(&self.shared.errors);
            return None;
        }
        let mut attempt = Attempt {
            sink: self.clone(),
            id,
            sequence: 0,
            lane,
            last_at: None,
            finished: false,
        };
        attempt.emit("attempt-started", build);
        Some(attempt)
    }
}
pub(super) struct Attempt {
    sink: Sink,
    id: u64,
    sequence: u64,
    lane: &'static str,
    last_at: Option<f64>,
    finished: bool,
}
impl Attempt {
    pub(super) fn diagnostic_id(&self) -> u64 {
        self.id
    }
    pub(super) fn diagnostic_error(&self) {
        bump(&self.sink.shared.errors);
    }
    fn emit(&mut self, phase: &str, build: impl FnOnce() -> Result<Value>) {
        if self.sink.shared.closed.load(Ordering::Acquire) {
            return;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Event> {
            require(label(phase), "Carriage phase bound")?;
            let at = super::monotonic()?;
            require(
                at.is_finite()
                    && at >= self.sink.shared.created_at
                    && self.last_at.is_none_or(|last| at >= last),
                "Carriage attempt clock moved backwards",
            )?;
            let sequence = self
                .sequence
                .checked_add(1)
                .ok_or("Carriage attempt sequence exhausted")?;
            let value = build()?;
            detail(&value)?;
            self.sequence = sequence;
            self.last_at = Some(at);
            Ok(Event {
                attempt: self.id,
                sequence,
                lane: self.lane,
                phase: phase.into(),
                observed_at: at,
                detail: value,
            })
        }));
        match result {
            Ok(Ok(event)) => self.sink.shared.send(event),
            Ok(Err(_)) | Err(_) => bump(&self.sink.shared.errors),
        }
    }
    pub(super) fn event(&mut self, phase: &str, build: impl FnOnce() -> Result<Value>) {
        if matches!(
            phase,
            "attempt-started" | "attempt-completed" | "attempt-abandoned"
        ) {
            bump(&self.sink.shared.errors);
            return;
        }
        self.emit(phase, build);
    }
    pub(super) fn finish(mut self, result: &Result<()>) {
        self.emit("attempt-completed", || Ok(match result {
            Ok(()) => json!({"result":"ok"}),
            Err(error) => {
                let prefix = error.split(':').next().unwrap_or("");
                let tag = if !prefix.is_empty() && prefix.len() <= 64
                    && prefix.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                    prefix
                } else { "OPERATION_ERROR" };
                json!({"result":"error","error_tag":tag,"lock_contention":super::lock_contention(error)})
            }
        }));
        self.finished = true;
        self.sink.shared.active.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.finished {
            bump(&self.sink.shared.incomplete);
            self.emit("attempt-abandoned", || Ok(json!({"result":"incomplete"})));
            self.sink.shared.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn private_root(root: &Path) -> Result<()> {
    files::private_path(root, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        require(
            meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
            "Carriage observation root must be private and owned",
        )?;
    }
    Ok(())
}
fn fresh(root: &Path) -> Result<()> {
    for name in [SCOPE, EVENTS, TERMINAL] {
        match fs::symlink_metadata(root.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("Carriage observation already exists; no resume".into()),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}
fn create(path: &Path) -> Result<File> {
    let file = files::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    retained_path(&file, path)?;
    Ok(file)
}
fn retained_path(file: &File, path: &Path) -> Result<()> {
    files::private_metadata(file)?;
    let path_meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    require(
        path_meta.is_file() && !path_meta.file_type().is_symlink(),
        "Carriage retained path type changed",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        require(
            meta.nlink() == 1 && path_meta.dev() == meta.dev() && path_meta.ino() == meta.ino(),
            "Carriage retained path identity or links changed",
        )?;
    }
    Ok(())
}
fn sync_root(root: &Path) -> Result<()> {
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
fn meta(root: &Path, name: &str, value: &Value) -> Result<(File, Vec<u8>)> {
    let raw = files::canonical_with_limit(value, MAX_META)?;
    let mut file = create(&root.join(name))?;
    file.write_all(&raw).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    sync_root(root)?;
    Ok((file, raw))
}
fn readback(file: &mut File, path: &Path, limit: usize) -> Result<Vec<u8>> {
    file.sync_all().map_err(|e| e.to_string())?;
    retained_path(file, path)?;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    require(
        file.metadata().map_err(|e| e.to_string())?.len() <= limit as u64,
        "Carriage retained byte bound",
    )?;
    let mut raw = Vec::new();
    (&mut *file)
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    require(
        raw.len() <= limit && file.metadata().map_err(|e| e.to_string())?.len() == raw.len() as u64,
        "Carriage retained bytes changed",
    )?;
    retained_path(file, path)?;
    Ok(raw)
}
struct Writer {
    root: PathBuf,
    binding: Value,
    scope: File,
    scope_raw: Vec<u8>,
    events: File,
    digest: Sha256,
    rows: usize,
    bytes: usize,
    poisoned: bool,
    latest_observed_at: f64,
}
impl Writer {
    fn append(&mut self, event: Event) -> Result<()> {
        require(!self.poisoned, "Carriage collector previously failed")?;
        let observed_at = event.observed_at;
        let mut row = self.binding.clone();
        let fields = row.as_object_mut().ok_or("Carriage binding invalid")?;
        fields.extend(
            serde_json::from_value::<serde_json::Map<String, Value>>(json!({
                "written_sequence":self.rows + 1,"attempt_id":event.attempt,
                "attempt_sequence":event.sequence,"lane":event.lane,"phase":event.phase,
                "observed_at":event.observed_at,"detail":event.detail
            }))
            .map_err(|e| e.to_string())?,
        );
        let mut raw = files::canonical_with_limit(&row, MAX_ROW - 1)?;
        raw.push(b'\n');
        let rows = self
            .rows
            .checked_add(1)
            .filter(|n| *n <= MAX_ROWS)
            .ok_or("Carriage row capacity")?;
        let bytes = self
            .bytes
            .checked_add(raw.len())
            .filter(|n| *n <= MAX_BYTES)
            .ok_or("Carriage byte capacity")?;
        self.events.write_all(&raw).map_err(|e| e.to_string())?;
        self.digest.update(&raw);
        self.latest_observed_at = self.latest_observed_at.max(observed_at);
        self.rows = rows;
        self.bytes = bytes;
        Ok(())
    }
    fn finish(&mut self, shared: &Shared) -> Result<()> {
        private_root(&self.root)?;
        let scope = readback(&mut self.scope, &self.root.join(SCOPE), MAX_META)?;
        let events = readback(&mut self.events, &self.root.join(EVENTS), MAX_BYTES)?;
        let retained_sha = hex::encode(Sha256::digest(&events));
        let written_sha = hex::encode(self.digest.clone().finalize());
        let integrity =
            scope == self.scope_raw && events.len() == self.bytes && retained_sha == written_sha;
        let loss = shared.loss.load(Ordering::Acquire);
        let errors = shared.errors.load(Ordering::Acquire);
        let incomplete = shared.incomplete.load(Ordering::Acquire);
        let active = shared.active.load(Ordering::Acquire);
        let handles = shared.handles.load(Ordering::Acquire);
        let requested = shared.requested_success.load(Ordering::Acquire);
        let completed_at = super::monotonic()?;
        require(
            completed_at.is_finite() && completed_at >= self.latest_observed_at,
            "Carriage terminal clock invalid",
        )?;
        let success = requested
            && integrity
            && !self.poisoned
            && loss == 0
            && errors == 0
            && incomplete == 0
            && active == 0
            && handles == 0;
        let mut terminal = self.binding.clone();
        terminal.as_object_mut().ok_or("Carriage terminal binding invalid")?.extend(
            serde_json::from_value::<serde_json::Map<String, Value>>(json!({
                "scope_sha256":hex::encode(Sha256::digest(&self.scope_raw)),
                "requested_success":requested,"success":success,"completed_at":completed_at,
                "rows":self.rows,"events_bytes":events.len(),"events_sha256":retained_sha,
                "complete_rows_bytes":self.bytes,"complete_rows_sha256":written_sha,
                "exact_retained_integrity":integrity,"loss":loss,"errors":errors,
                "incomplete_attempts":incomplete,"active_attempts":active,"remaining_sink_handles":handles,
                "attempts_started":shared.next_attempt.load(Ordering::Acquire),
                "collector_poisoned":self.poisoned,"global_clock_order_claim":false,
                "worker_join_qualified":false
            })).map_err(|e| e.to_string())?);
        let (mut file, raw) = meta(&self.root, TERMINAL, &terminal)?;
        require(
            readback(&mut file, &self.root.join(TERMINAL), MAX_META)? == raw,
            "Carriage terminal readback differs",
        )?;
        sync_root(&self.root)?;
        require(
            !requested || success,
            "Carriage incomplete observation cannot seal true",
        )
    }
}
fn collect(mut writer: Writer, rx: Receiver<Event>, shared: Arc<Shared>) -> Result<()> {
    loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => {
                if writer.append(event).is_err() {
                    writer.poisoned = true;
                    bump(&shared.errors);
                }
            }
            Err(RecvTimeoutError::Timeout) if shared.closed.load(Ordering::Acquire) => break,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                bump(&shared.errors);
                break;
            }
        }
    }
    if shared.seal_requested.load(Ordering::Acquire) {
        writer.finish(&shared)
    } else {
        // A missing explicit finish retains bytes, but never invents a closure footer.
        writer.events.sync_all().map_err(|e| e.to_string())?;
        sync_root(&writer.root)?;
        Err("Carriage observation dropped without explicit finish".into())
    }
}
#[must_use]
pub(super) struct Guard {
    shared: Arc<Shared>,
    collector: Option<JoinHandle<Result<()>>>,
    finish_started: bool,
    _thread_affine: PhantomData<Rc<()>>,
}
impl Guard {
    pub(super) fn sink(&self) -> Option<Sink> {
        if self.shared.closed.load(Ordering::Acquire) {
            return None;
        }
        self.shared.add_handle();
        Some(Sink {
            shared: Arc::clone(&self.shared),
        })
    }
    /// Root must first join ordinary workers and release every Sink/Attempt.
    pub(super) fn finish(mut self, success: bool) -> Result<()> {
        self.finish_started = true;
        if self.shared.handles.load(Ordering::Acquire) != 0 {
            bump(&self.shared.errors);
        }
        self.shared
            .requested_success
            .store(success, Ordering::Release);
        self.shared.seal_requested.store(true, Ordering::Release);
        self.shared.closed.store(true, Ordering::Release);
        self.collector
            .take()
            .ok_or("Carriage collector absent")?
            .join()
            .map_err(|_| "Carriage collector panicked".to_string())?
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.finish_started {
            bump(&self.shared.incomplete);
            self.shared.closed.store(true, Ordering::Release);
            // Drop never joins, waits for a disk write, or creates a true footer.
        }
    }
}
pub(super) fn start(
    enabled: bool,
    root: &Path,
    instance: &str,
    currency: Hash,
    region: Hash,
    node_id: &str,
) -> Result<Option<Guard>> {
    if !enabled {
        return Ok(None);
    }
    private_root(root)?;
    fresh(root)?;
    require(
        identifier(instance) && identifier(node_id) && identifier(env!("RLD_REGIONAL_SOURCE")),
        "Carriage observation exact identifier required",
    )?;
    let created_at = super::monotonic()?;
    require(
        created_at.is_finite() && created_at >= 0.0,
        "Carriage observation clock invalid",
    )?;
    let binding = json!({"format":FORMAT,"pid":std::process::id(),"instance":instance,
        "currency":currency,"region":region,"node_id":node_id,
        "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
        "diagnostic_only":true,"native_authority":false,"signing_authority":false,
        "custody_acknowledgment":false,"payment_qualification":false,
        "independent_freshness_qualified":false});
    let mut scope_value = binding.clone();
    scope_value
        .as_object_mut()
        .ok_or("Carriage scope binding invalid")?
        .extend(
            serde_json::from_value::<serde_json::Map<String, Value>>(json!({
                "created_at":created_at,"clock":"local-monotonic-seconds",
                "max_rows":MAX_ROWS,"max_bytes":MAX_BYTES,"max_row_bytes":MAX_ROW,
                "channel_capacity":CHANNEL,"written_order_is_global_clock_order":false
            }))
            .map_err(|e| e.to_string())?,
        );
    let (scope, scope_raw) = meta(root, SCOPE, &scope_value)?;
    let events = create(&root.join(EVENTS))?;
    events.sync_all().map_err(|e| e.to_string())?;
    sync_root(root)?;
    let (tx, rx) = sync_channel(CHANNEL);
    let shared = Arc::new(Shared {
        tx,
        created_at,
        closed: AtomicBool::new(false),
        seal_requested: AtomicBool::new(false),
        requested_success: AtomicBool::new(false),
        next_attempt: AtomicU64::new(0),
        active: AtomicU64::new(0),
        handles: AtomicUsize::new(0),
        loss: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        incomplete: AtomicU64::new(0),
    });
    let writer = Writer {
        root: root.into(),
        binding,
        scope,
        scope_raw,
        events,
        digest: Sha256::new(),
        rows: 0,
        bytes: 0,
        poisoned: false,
        latest_observed_at: created_at,
    };
    let collector_shared = Arc::clone(&shared);
    let collector = thread::Builder::new()
        .name("rld-carriage-observer".into())
        .spawn(move || collect(writer, rx, collector_shared))
        .map_err(|e| e.to_string())?;
    Ok(Some(Guard {
        shared,
        collector: Some(collector),
        finish_started: false,
        _thread_affine: PhantomData,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn diagnostic_directory() -> PathBuf {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-carriage-observer-{}-{}",
                std::process::id(),
                super::super::monotonic().unwrap().to_bits()
            ));
        let mut create = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            create.mode(0o700);
        }
        create.create(&root).unwrap();
        root
    }
    fn new_guard(root: &Path) -> Guard {
        start(
            true,
            root,
            &"a".repeat(64),
            Hash::ZERO,
            Hash::ZERO,
            &"b".repeat(64),
        )
        .unwrap()
        .unwrap()
    }
    fn terminal(root: &Path) -> Value {
        serde_json::from_slice(&fs::read(root.join(TERMINAL)).unwrap()).unwrap()
    }
    #[test]
    fn disabled_is_lazy_and_environment_is_exact() {
        assert!(start(
            false,
            Path::new("/not/a/real/private/root"),
            "invalid",
            Hash::ZERO,
            Hash::ZERO,
            "invalid"
        )
        .unwrap()
        .is_none());
        let sink: Option<Sink> = None;
        let attempt = sink
            .as_ref()
            .and_then(|s| s.begin_attempt("outgoing", || panic!("disabled closure evaluated")));
        assert!(attempt.is_none());
        assert!(!parse_enabled(None).unwrap());
        assert!(parse_enabled(Some(OsStr::new("1"))).unwrap());
        for text in ["", "0", "true", " 1", "1 "] {
            assert!(parse_enabled(Some(OsStr::new(text))).is_err());
        }
    }
    #[test]
    fn exact_trace_and_resume_refusal() {
        let root = diagnostic_directory();
        let guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        let mut attempt = sink
            .begin_attempt("outgoing", || Ok(json!({"packet_ids":["c".repeat(64)]})))
            .unwrap();
        attempt.event("challenge-received", || Ok(json!({"packet_count":1})));
        attempt.finish(&Err("TLS_IO: original operation still failed".into()));
        drop(sink);
        guard.finish(true).unwrap();
        let terminal = terminal(&root);
        let raw = fs::read(root.join(EVENTS)).unwrap();
        assert_eq!(terminal["success"], true);
        assert_eq!(terminal["rows"], 3);
        assert_eq!(terminal["events_sha256"], hex::encode(Sha256::digest(&raw)));
        assert_eq!(terminal["native_authority"], false);
        assert_eq!(terminal["worker_join_qualified"], false);
        assert!(start(
            true,
            &root,
            &"a".repeat(64),
            Hash::ZERO,
            Hash::ZERO,
            &"b".repeat(64)
        )
        .is_err());
        assert_eq!(fs::read(root.join(EVENTS)).unwrap(), raw);
    }
    #[test]
    fn unfinished_attempt_or_live_sink_refuses_true() {
        let root = diagnostic_directory();
        let guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        drop(sink.begin_attempt("inbound", || Ok(json!({}))).unwrap());
        drop(sink);
        assert!(guard.finish(true).is_err());
        assert_eq!(terminal(&root)["incomplete_attempts"], 1);
        assert_eq!(terminal(&root)["success"], false);
        let root = diagnostic_directory();
        let guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        assert!(guard.finish(true).is_err());
        assert_eq!(terminal(&root)["success"], false);
        drop(sink);
    }
    #[test]
    fn missing_guard_finish_has_no_fabricated_footer() {
        let root = diagnostic_directory();
        let mut guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        sink.begin_attempt("outgoing", || Ok(json!({})))
            .unwrap()
            .finish(&Ok(()));
        drop(sink);
        let collector = guard.collector.take().unwrap();
        drop(guard);
        assert!(collector.join().unwrap().is_err());
        assert!(!root.join(TERMINAL).exists());
        assert!(!fs::read(root.join(EVENTS)).unwrap().is_empty());
    }
    #[test]
    fn retained_events_or_scope_tamper_refuses_true() {
        for name in [EVENTS, SCOPE] {
            let root = diagnostic_directory();
            let guard = new_guard(&root);
            let sink = guard.sink().unwrap();
            sink.begin_attempt("outgoing", || Ok(json!({})))
                .unwrap()
                .finish(&Ok(()));
            drop(sink);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while fs::read(root.join(EVENTS))
                .unwrap()
                .iter()
                .filter(|b| **b == b'\n')
                .count()
                < 2
            {
                assert!(
                    std::time::Instant::now() < deadline,
                    "collector did not write both rows"
                );
                thread::sleep(Duration::from_millis(1));
            }
            let mut file = files::options().append(true).open(root.join(name)).unwrap();
            file.write_all(b"\n").unwrap();
            file.sync_all().unwrap();
            assert!(guard.finish(true).is_err());
            assert_eq!(terminal(&root)["success"], false);
        }
    }
    #[test]
    fn full_channel_retains_loss_outside_queue() {
        // No collector consumes this test queue: capacity refusal is deterministic.
        let (tx, rx) = sync_channel(1);
        let shared = Arc::new(Shared {
            tx,
            created_at: 0.0,
            closed: AtomicBool::new(false),
            seal_requested: AtomicBool::new(false),
            requested_success: AtomicBool::new(false),
            next_attempt: AtomicU64::new(0),
            active: AtomicU64::new(0),
            handles: AtomicUsize::new(1),
            loss: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            incomplete: AtomicU64::new(0),
        });
        let sink = Sink {
            shared: Arc::clone(&shared),
        };
        let mut attempt = sink.begin_attempt("outgoing", || Ok(json!({}))).unwrap();
        attempt.event("challenge", || Ok(json!({})));
        attempt.finish(&Ok(()));
        assert_eq!(shared.loss.load(Ordering::Acquire), 2);
        assert_eq!(shared.active.load(Ordering::Acquire), 0);
        drop(sink);
        let root = diagnostic_directory();
        let binding = json!({"format":FORMAT,"pid":std::process::id(),"instance":"a".repeat(64),
            "currency":Hash::ZERO,"region":Hash::ZERO,"node_id":"b".repeat(64),
            "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
            "diagnostic_only":true,"native_authority":false,"custody_acknowledgment":false,
            "signing_authority":false,"payment_qualification":false,"independent_freshness_qualified":false});
        let (scope, scope_raw) = meta(&root, SCOPE, &binding).unwrap();
        let events = create(&root.join(EVENTS)).unwrap();
        let writer = Writer {
            root: root.clone(),
            binding,
            scope,
            scope_raw,
            events,
            digest: Sha256::new(),
            rows: 0,
            bytes: 0,
            poisoned: false,
            latest_observed_at: 0.0,
        };
        shared.requested_success.store(true, Ordering::Release);
        shared.seal_requested.store(true, Ordering::Release);
        shared.closed.store(true, Ordering::Release);
        assert!(collect(writer, rx, Arc::clone(&shared)).is_err());
        assert_eq!(terminal(&root)["success"], false);
        assert_eq!(terminal(&root)["loss"], 2);
        assert_eq!(terminal(&root)["rows"], 1);
    }
    #[test]
    fn concurrent_attempt_sequences_are_separate_from_written_order() {
        let root = diagnostic_directory();
        let guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel(1);
        let first = sink.clone();
        let thread = thread::spawn(move || {
            first
                .begin_attempt("outgoing", || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(json!({}))
                })
                .unwrap()
                .finish(&Ok(()));
        });
        entered_rx.recv().unwrap();
        sink.begin_attempt("inbound", || Ok(json!({})))
            .unwrap()
            .finish(&Ok(()));
        release_tx.send(()).unwrap();
        thread.join().unwrap();
        drop(sink);
        guard.finish(true).unwrap();
        let raw = fs::read(root.join(EVENTS)).unwrap();
        let rows: Vec<Value> = raw
            .split(|b| *b == b'\n')
            .filter(|r| !r.is_empty())
            .map(|r| serde_json::from_slice(r).unwrap())
            .collect();
        assert_eq!(rows[0]["attempt_id"], 2);
        assert_eq!(rows[2]["attempt_id"], 1);
        assert!(
            rows[2]["observed_at"].as_f64().unwrap() <= rows[0]["observed_at"].as_f64().unwrap()
        );
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row["written_sequence"], i + 1);
        }
        for pair in rows.chunks(2) {
            assert_eq!(pair[0]["attempt_sequence"], 1);
            assert_eq!(pair[1]["attempt_sequence"], 2);
        }
    }
    #[test]
    fn invalid_metadata_or_reserved_phase_refuses_success_without_operation_error() {
        let root = diagnostic_directory();
        let guard = new_guard(&root);
        let sink = guard.sink().unwrap();
        let mut attempt = sink
            .begin_attempt("outgoing", || Ok(json!({"payload":"forbidden"})))
            .unwrap();
        attempt.event("attempt-completed", || {
            panic!("reserved phase closure evaluated")
        });
        let original: Result<()> = Err("ORIGINAL_FAILURE".into());
        attempt.finish(&original);
        assert_eq!(original, Err("ORIGINAL_FAILURE".into()));
        drop(sink);
        assert!(guard.finish(true).is_err());
        assert_eq!(terminal(&root)["success"], false);
    }
}

#[cfg(test)]
mod metadata_boundary_tests {
    use super::*;
    #[test]
    fn exact_four_packet_metadata_and_raw_rejections() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Sink>();
        let ids = vec!["c".repeat(64); 4];
        assert!(
            detail(&json!({"peer":"f".repeat(64),"exchange_id":"a".repeat(64),
            "packet_ids":ids,"frame_ids":vec!["d".repeat(64);4],
            "destination_ids":vec!["e".repeat(64);4],"receipt_count":0}))
            .is_ok()
        );
        assert!(detail(&json!({"packet_ids":vec!["c".repeat(64);5]})).is_err());
        for raw in [
            json!({"exchange":{"packet_ids":[]}}),
            json!({"config":{"node_id":"a".repeat(64)}}),
            json!({"path":"/private/state"}),
            json!({"payload":"raw material"}),
            json!({"error":"TLS_IO: /private/key"}),
        ] {
            assert!(detail(&raw).is_err());
        }
    }
}

#[cfg(test)]
#[path = "service_mesh_lease_tests.rs"]
mod mesh_lease_tests;
