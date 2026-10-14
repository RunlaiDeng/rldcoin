//! Default-disabled, bounded local diagnostics; never Native or custody authority.
//! One Service main thread owns the writer. Worker threads have no writer.
use crate::{require, wallet_client as files, Hash, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
};

const FORMAT: &str = "RLD-SERVICE-NATIVE-OBSERVATION-V1";
const ENV: &str = "RLD_SERVICE_NATIVE_OBSERVATION";
const MAX_ROWS: usize = 16_384;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROW: usize = 256 * 1024;
const MAX_META: usize = 64 * 1024;
const SCOPE: &str = "native-schedule-scope.json";
const EVENTS: &str = "native-schedule-events.jsonl";
const TERMINAL: &str = "native-schedule-terminal.json";

thread_local! {
    static WRITER: RefCell<Option<Writer>> = const { RefCell::new(None) };
}

fn parse_enabled(value: Option<&OsStr>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(_) => Err("Native observation env must be absent or exactly 1".into()),
    }
}
pub(super) fn enabled_from_env() -> Result<bool> {
    parse_enabled(std::env::var_os(ENV).as_deref())
}

fn private_root(root: &Path) -> Result<()> {
    files::private_path(root, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        require(
            meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
            "Native observation root must be private and owned",
        )?;
    }
    Ok(())
}
fn fresh(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Native observation file already exists; no resume".into()),
        Err(error) => Err(error.to_string()),
    }
}
fn create(path: &Path) -> Result<File> {
    let file = files::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    files::private_metadata(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            file.metadata().map_err(|e| e.to_string())?.nlink() == 1,
            "Native observation file link count differs",
        )?;
    }
    Ok(file)
}
fn sync_root(root: &Path) -> Result<()> {
    File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}
fn new_meta(root: &Path, name: &str, value: &Value) -> Result<Vec<u8>> {
    let raw = files::canonical_with_limit(value, MAX_META)?;
    let mut file = create(&root.join(name))?;
    file.write_all(&raw).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    sync_root(root)?;
    Ok(raw)
}
fn identifier(value: &str) -> Result<()> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Native observation identifier must be exact lowercase 32-byte hex",
    )
}
fn phase_name(phase: &str) -> Result<()> {
    require(
        !phase.is_empty()
            && phase.len() <= 96
            && phase
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "Native observation phase name bound",
    )
}
fn reserve(rows: usize, bytes: usize, row_bytes: usize) -> Result<(usize, usize)> {
    require(row_bytes <= MAX_ROW, "Native observation row byte bound")?;
    let rows = rows
        .checked_add(1)
        .filter(|rows| *rows <= MAX_ROWS)
        .ok_or("Native observation row count bound")?;
    let bytes = bytes
        .checked_add(row_bytes)
        .filter(|bytes| *bytes <= MAX_BYTES)
        .ok_or("Native observation total byte bound")?;
    Ok((rows, bytes))
}

struct Last {
    at: f64,
    phase: String,
}
struct Writer {
    root: PathBuf,
    instance: String,
    scope_sha256: String,
    created_at: f64,
    file: File,
    digest: Sha256,
    bytes: usize,
    rows: usize,
    turns: u64,
    active_turn: Option<u64>,
    turn_started: Option<f64>,
    last: Option<Last>,
    poisoned: bool,
    sealed: bool,
}
impl Writer {
    fn append(&mut self, phase: &str, detail: Value) -> Result<()> {
        phase_name(phase)?;
        let turn = self.active_turn.ok_or("Native observation turn absent")?;
        let started = self
            .turn_started
            .ok_or("Native observation turn start absent")?;
        let at = super::monotonic()?;
        require(
            at.is_finite()
                && at >= started
                && at >= self.created_at
                && self.last.as_ref().is_none_or(|last| at >= last.at),
            "Native observation row clock moved backwards",
        )?;
        let sequence = self
            .rows
            .checked_add(1)
            .ok_or("Native observation sequence exhausted")?;
        let row = json!({"sequence":sequence,"turn":turn,"at":at,
            "phase":phase,"detail":detail});
        let mut raw = files::canonical_with_limit(&row, MAX_ROW - 1)?;
        raw.push(b'\n');
        let (rows, bytes) = reserve(self.rows, self.bytes, raw.len())?;
        self.file.write_all(&raw).map_err(|e| e.to_string())?;
        // Advance only after a whole row has reached the file. A partial write
        // stays retained and cannot produce a true terminal prefix match.
        self.digest.update(&raw);
        self.rows = rows;
        self.bytes = bytes;
        self.last = Some(Last {
            at,
            phase: phase.into(),
        });
        Ok(())
    }

    fn retained_digest(&mut self) -> Result<(usize, String)> {
        self.file.sync_all().map_err(|e| e.to_string())?;
        files::private_metadata(&self.file)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut digest = Sha256::new();
        let mut bytes = 0usize;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let wanted = (MAX_BYTES + 1 - bytes).min(buffer.len());
            let read = self
                .file
                .read(&mut buffer[..wanted])
                .map_err(|e| e.to_string())?;
            if read == 0 {
                break;
            }
            bytes += read;
            require(bytes <= MAX_BYTES, "Native observation retained byte bound")?;
            digest.update(&buffer[..read]);
        }
        require(
            self.file.metadata().map_err(|e| e.to_string())?.len() == bytes as u64,
            "Native observation retained length changed",
        )?;
        Ok((bytes, hex::encode(digest.finalize())))
    }

    fn finish(&mut self, requested_success: bool) -> Result<()> {
        require(!self.sealed, "Native observation already sealed")?;
        private_root(&self.root)?;
        let (retained_bytes, retained_sha256) = self.retained_digest()?;
        let prefix_sha256 = hex::encode(self.digest.clone().finalize());
        let prefix_integrity = retained_bytes == self.bytes && retained_sha256 == prefix_sha256;
        let at = super::monotonic()?;
        require(
            at.is_finite()
                && at >= self.created_at
                && self.last.as_ref().is_none_or(|last| at >= last.at),
            "Native observation terminal clock moved backwards",
        )?;
        let success =
            requested_success && !self.poisoned && self.active_turn.is_none() && prefix_integrity;
        let terminal = json!({"format":FORMAT,"scope_sha256":self.scope_sha256,
            "requested_success":requested_success,"success":success,"completed_at":at,
            "rows":self.rows,"turns":self.turns,"active_turn":self.active_turn,
            "events_bytes":retained_bytes,"events_sha256":retained_sha256,
            "complete_rows_bytes":self.bytes,"complete_rows_sha256":prefix_sha256,
            "complete_rows_match_retained_bytes":prefix_integrity,
            "last_sequence":self.last.as_ref().map(|_|self.rows),
            "last_at":self.last.as_ref().map(|last|last.at),
            "last_phase":self.last.as_ref().map(|last|&last.phase),
            "observer_error":self.poisoned,"diagnostic_only":true,
            "native_authority":false,"signing_authority":false,
            "custody_acknowledgment":false,"payment_qualification":false,
            "independent_freshness_qualified":false});
        new_meta(&self.root, TERMINAL, &terminal)?;
        self.sealed = true;
        require(
            !requested_success || success,
            "Native observation cannot seal an incomplete trace as successful",
        )
    }
}

fn with_writer(operation: impl FnOnce(&mut Writer) -> Result<()>) -> Result<()> {
    WRITER.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "Native observation writer reentry")?;
        let Some(writer) = slot.as_mut() else {
            return Ok(());
        };
        require(
            !writer.poisoned && !writer.sealed,
            "Native observation writer previously failed or sealed",
        )?;
        let result = operation(writer);
        if result.is_err() {
            writer.poisoned = true;
        }
        result
    })
}

/// Thread-affine so one main thread owns every turn and its false Drop terminal.
#[must_use]
pub(super) struct Guard {
    instance: String,
    finished: bool,
    _thread_affine: PhantomData<Rc<()>>,
}
impl Guard {
    pub(super) fn finish(mut self, success: bool) -> Result<()> {
        WRITER.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| "Native observation finish reentry")?;
            let writer = slot.as_mut().ok_or("Native observation writer absent")?;
            require(
                writer.instance == self.instance,
                "Native observation guard belongs to another instance",
            )?;
            let result = writer.finish(success);
            if writer.sealed {
                slot.take();
                self.finished = true;
            }
            result
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let result = WRITER.with(|slot| {
            let mut slot = slot
                .try_borrow_mut()
                .map_err(|_| "Native observation Drop reentry")?;
            let writer = slot
                .as_mut()
                .ok_or("Native observation Drop writer absent")?;
            require(
                writer.instance == self.instance,
                "Native observation Drop guard belongs to another instance",
            )?;
            let result = writer.finish(false);
            // Retained files/residue survive failure. Never leave a previous
            // instance's writer active for a later Service call on this thread.
            slot.take();
            result
        });
        if let Err(error) = result {
            eprintln!("Native observation false terminal refused: {error}");
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
    WRITER.with(|slot| {
        let mut slot = slot
            .try_borrow_mut()
            .map_err(|_| "Native observation start reentry")?;
        require(slot.is_none(), "Native observation already active")?;
        private_root(root)?;
        identifier(instance)?;
        identifier(node_id)?;
        for name in [SCOPE, EVENTS, TERMINAL] {
            fresh(&root.join(name))?;
        }
        let created_at = super::monotonic()?;
        require(
            created_at.is_finite() && created_at >= 0.0,
            "Native observation start clock invalid",
        )?;
        let scope = json!({"format":FORMAT,"pid":std::process::id(),
            "instance":instance,"currency":currency,"region":region,"node_id":node_id,
            "regional_build_source_sha256":env!("RLD_REGIONAL_SOURCE"),
            "created_at":created_at,"clock":"local-monotonic-seconds",
            "max_rows":MAX_ROWS,"max_bytes":MAX_BYTES,"max_row_bytes":MAX_ROW,
            "diagnostic_only":true,"native_authority":false,"signing_authority":false,
            "custody_acknowledgment":false,"payment_qualification":false,
            "independent_freshness_qualified":false});
        let scope_raw = new_meta(root, SCOPE, &scope)?;
        let file = create(&root.join(EVENTS))?;
        file.sync_all().map_err(|e| e.to_string())?;
        sync_root(root)?;
        *slot = Some(Writer {
            root: root.to_path_buf(),
            instance: instance.into(),
            scope_sha256: hex::encode(Sha256::digest(scope_raw)),
            created_at,
            file,
            digest: Sha256::new(),
            bytes: 0,
            rows: 0,
            turns: 0,
            active_turn: None,
            turn_started: None,
            last: None,
            poisoned: false,
            sealed: false,
        });
        Ok(Some(Guard {
            instance: instance.into(),
            finished: false,
            _thread_affine: PhantomData,
        }))
    })
}

pub(super) fn begin_turn(turn_started: f64) -> Result<()> {
    with_writer(|writer| {
        require(
            writer.active_turn.is_none(),
            "Native observation previous turn has no end",
        )?;
        require(
            turn_started.is_finite()
                && turn_started >= writer.created_at
                && writer
                    .last
                    .as_ref()
                    .is_none_or(|last| turn_started >= last.at),
            "Native observation turn start clock invalid",
        )?;
        writer.turns = writer
            .turns
            .checked_add(1)
            .ok_or("Native observation turn counter exhausted")?;
        writer.active_turn = Some(writer.turns);
        writer.turn_started = Some(turn_started);
        writer.append("turn-start", json!({"started_at":turn_started}))
    })
}
pub(in crate::contact_runtime) fn event(
    phase: &str,
    detail: impl FnOnce() -> Result<Value>,
) -> Result<()> {
    with_writer(|writer| {
        require(
            phase != "turn-start" && phase != "turn-end",
            "Native observation reserved turn phase",
        )?;
        writer.append(phase, detail()?)
    })
}
pub(super) fn end_turn(result: &Result<Value>) -> Result<()> {
    with_writer(|writer| {
        let detail = match result {
            Ok(value) => json!({"result":"ok","observation":value}),
            Err(error) => json!({"result":if super::lock_contention(error) {
                "lock-contention"
            } else {
                "error"
            },"error":error}),
        };
        writer.append("turn-end", detail)?;
        writer.active_turn = None;
        writer.turn_started = None;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic_directory() -> PathBuf {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = parent.join(format!(
            "rld-native-observer-{}-{}",
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

    fn new_writer(root: &Path) -> Guard {
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

    #[test]
    fn complete_trace_seals_exact_retained_bytes_and_refuses_resume() {
        let root = diagnostic_directory();
        let guard = new_writer(&root);
        begin_turn(super::super::monotonic().unwrap()).unwrap();
        event("native-complete", || Ok(json!({"height":1}))).unwrap();
        end_turn(&Ok(json!({"progress_observation_available":true}))).unwrap();
        guard.finish(true).unwrap();
        let scope = files::private_read_with_limit(&root.join(SCOPE), MAX_META).unwrap();
        let events = files::private_read_with_limit(&root.join(EVENTS), MAX_BYTES).unwrap();
        let terminal: Value = serde_json::from_slice(
            &files::private_read_with_limit(&root.join(TERMINAL), MAX_META).unwrap(),
        )
        .unwrap();
        assert_eq!(terminal["success"], true);
        assert_eq!(terminal["rows"], 3);
        assert_eq!(terminal["turns"], 1);
        assert_eq!(terminal["active_turn"], Value::Null);
        assert_eq!(terminal["last_phase"], "turn-end");
        assert_eq!(
            terminal["scope_sha256"],
            hex::encode(Sha256::digest(&scope))
        );
        assert_eq!(
            terminal["events_sha256"],
            hex::encode(Sha256::digest(&events))
        );
        assert_eq!(terminal["events_bytes"], events.len());
        assert_eq!(terminal["complete_rows_match_retained_bytes"], true);
        assert_eq!(terminal["native_authority"], false);
        let rows: Vec<Value> = events
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["sequence"], index + 1);
            assert_eq!(row["turn"], 1);
            if index > 0 {
                assert!(row["at"].as_f64().unwrap() >= rows[index - 1]["at"].as_f64().unwrap());
            }
        }
        assert!(start(
            true,
            &root,
            &"a".repeat(64),
            Hash::ZERO,
            Hash::ZERO,
            &"b".repeat(64)
        )
        .is_err());
        assert_eq!(fs::read(root.join(EVENTS)).unwrap(), events);
        // Retain this small diagnostic-only image, including failure residue.
        // It contains no Native store, runtime custody, private key or value.
    }

    #[test]
    fn unfinished_drop_has_false_terminal_and_preserves_open_turn() {
        let root = diagnostic_directory();
        let guard = new_writer(&root);
        begin_turn(super::super::monotonic().unwrap()).unwrap();
        event("runtime-tick-start", || Ok(json!({"height":1}))).unwrap();
        drop(guard);
        let terminal: Value = serde_json::from_slice(
            &files::private_read_with_limit(&root.join(TERMINAL), MAX_META).unwrap(),
        )
        .unwrap();
        assert_eq!(terminal["success"], false);
        assert_eq!(terminal["rows"], 2);
        assert_eq!(terminal["active_turn"], 1);
        assert_eq!(terminal["last_phase"], "runtime-tick-start");
        assert_eq!(terminal["payment_qualification"], false);
        WRITER.with(|writer| assert!(writer.borrow().is_none()));
    }

    #[test]
    fn changed_retained_bytes_cannot_seal_as_success() {
        let root = diagnostic_directory();
        let guard = new_writer(&root);
        begin_turn(super::super::monotonic().unwrap()).unwrap();
        end_turn(&Err("original proof refusal".into())).unwrap();
        let mut other = files::options()
            .append(true)
            .open(root.join(EVENTS))
            .unwrap();
        other.write_all(b"\n").unwrap();
        other.sync_all().unwrap();
        assert!(guard.finish(true).is_err());
        let actual = fs::read(root.join(EVENTS)).unwrap();
        let terminal: Value = serde_json::from_slice(
            &files::private_read_with_limit(&root.join(TERMINAL), MAX_META).unwrap(),
        )
        .unwrap();
        assert_eq!(terminal["success"], false);
        assert_eq!(terminal["complete_rows_match_retained_bytes"], false);
        assert_eq!(terminal["events_bytes"], actual.len());
        assert_eq!(
            terminal["events_sha256"],
            hex::encode(Sha256::digest(&actual))
        );
        assert_ne!(terminal["events_sha256"], terminal["complete_rows_sha256"]);
        assert_eq!(terminal["last_phase"], "turn-end");
        WRITER.with(|writer| assert!(writer.borrow().is_none()));
    }

    #[test]
    fn disabled_events_are_lazy_and_have_no_clock_or_path_requirements() {
        WRITER.with(|writer| assert!(writer.borrow().is_none()));
        let guard = start(
            false,
            Path::new("missing-relative-path"),
            "bad",
            Hash::ZERO,
            Hash::ZERO,
            "bad",
        )
        .unwrap();
        assert!(guard.is_none());
        begin_turn(f64::NAN).unwrap();
        event("invalid phase", || panic!("disabled closure executed")).unwrap();
        end_turn(&Err("retained original failure".into())).unwrap();
        WRITER.with(|writer| assert!(writer.borrow().is_none()));
    }

    #[test]
    fn only_absent_or_exact_one_enable_observation() {
        assert!(!parse_enabled(None).unwrap());
        assert!(parse_enabled(Some(OsStr::new("1"))).unwrap());
        for value in ["", "0", "true", "01", "1 ", " 1"] {
            assert!(parse_enabled(Some(OsStr::new(value))).is_err());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(parse_enabled(Some(OsStr::from_bytes(&[0xff]))).is_err());
        }
    }

    #[test]
    fn exact_row_and_byte_limits_refuse_without_overflow() {
        assert_eq!(
            reserve(MAX_ROWS - 1, MAX_BYTES - 2, 2).unwrap(),
            (MAX_ROWS, MAX_BYTES)
        );
        for (rows, bytes, length) in [
            (MAX_ROWS, 0, 1),
            (0, MAX_BYTES, 1),
            (0, 0, MAX_ROW + 1),
            (usize::MAX, 0, 1),
            (0, usize::MAX, 1),
        ] {
            assert!(reserve(rows, bytes, length).is_err());
        }
    }

    #[test]
    fn phase_and_identifier_bounds_do_not_accept_unbounded_names() {
        phase_name("runtime-tick-result").unwrap();
        for value in ["", "bad space", "../parent", "UPPER"] {
            assert!(phase_name(value).is_err());
        }
        assert!(phase_name(&"a".repeat(97)).is_err());
        identifier(&"f".repeat(64)).unwrap();
        for value in [
            "f".repeat(63),
            "f".repeat(65),
            "F".repeat(64),
            "g".repeat(64),
        ] {
            assert!(identifier(&value).is_err());
        }
    }
}
