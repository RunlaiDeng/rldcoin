//! Bounded opaque file/queue IO; neither bytes nor durable IO authorize value.
use crate::{
    contact::{MAX_FRAME, MAX_PAYLOAD},
    contact_crypto::{buffer, output_with},
    contact_frame::inspect_bytes,
    contact_spool::names_bounded,
    contact_spool_codec::CodecOutput,
    contact_storage::{directory, io_error, open_at, parts},
    require, wallet_client, Hash, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};
const FORMAT: &str = "RLD-NATIVE-EVIDENCE-FILES-V1";
const MAX_FILE: usize = 64 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_BYTES: usize = 256 * 1024 * 1024;
const CONTROL: usize = 8192;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    files: usize,
    bytes: usize,
    frame: usize,
    payload: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.files <= MAX_FILES
                && self.bytes <= MAX_BYTES
                && self.frame <= MAX_FRAME
                && self.payload <= MAX_PAYLOAD,
            "native evidence queue limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Ensure {
        path: PathBuf,
    },
    Read {
        path: PathBuf,
        limit: usize,
    },
    Write {
        path: PathBuf,
        same: bool,
        retained_limit: usize,
        size_bytes: usize,
        sha256: String,
    },
    Receive {
        path: PathBuf,
        source: Option<String>,
        destination: Option<String>,
        limits: Limits,
        size_bytes: usize,
        sha256: String,
    },
    Carry {
        path: PathBuf,
        message_id: String,
        output: PathBuf,
        source: Option<String>,
        destination: Option<String>,
        limits: Limits,
    },
}
fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn value(raw: &[u8]) -> Value {
    json!({"format":FORMAT,"size_bytes":raw.len(),"sha256":sha(raw),"ledger_authority":false,"custody_acknowledgment":false})
}
fn ensure(path: &Path) -> Result<File> {
    require(path.is_absolute(), "evidence path must be absolute")?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(io_error)?;
    directory(path).map_err(|e| format!("unsafe directory: {e}"))
}
fn read_at(dir: &File, name: &std::ffi::OsStr, limit: usize) -> Result<(File, Vec<u8>)> {
    require(limit <= MAX_FILE, "native evidence read bound")?;
    let mut file = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK).map_err(|e| {
        if e.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::ELOOP)) {
            "unsafe or oversized file".into()
        } else {
            e
        }
    })?;
    require(
        file.metadata().map_err(io_error)?.len() <= limit as u64,
        "unsafe or oversized file",
    )?;
    let mut bytes = vec![];
    (&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    require(bytes.len() <= limit, "file grew beyond bound")?;
    Ok((file, bytes))
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let (parent, name) = parts(path)?;
    let dir = directory(parent)?;
    Ok(read_at(&dir, name, limit)?.1)
}
fn write_at(
    dir: &File,
    name: &std::ffi::OsStr,
    raw: &[u8],
    retained_limit: Option<usize>,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<()> {
    require(raw.len() <= MAX_FILE, "native evidence write bound")?;
    let opened = open_at(dir, name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL);
    let mut file = match opened {
        Ok(file) => file,
        Err(error)
            if retained_limit.is_some()
                && error.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::EEXIST)) =>
        {
            let (file, bytes) = read_at(dir, name, retained_limit.ok_or("retained limit absent")?)?;
            require(bytes == raw, "existing evidence differs")?;
            file.sync_all().map_err(io_error)?;
            dir.sync_all().map_err(io_error)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    observe("zero")?;
    let half = raw.len() / 2;
    file.write_all(&raw[..half]).map_err(io_error)?;
    observe("partial")?;
    file.write_all(&raw[half..]).map_err(io_error)?;
    observe("written")?;
    file.sync_all().map_err(io_error)?;
    observe("file")?;
    dir.sync_all().map_err(io_error)?;
    observe("directory")?;
    Ok(())
}
fn write(
    path: &Path,
    raw: &[u8],
    retained_limit: Option<usize>,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<()> {
    let (parent, name) = parts(path)?;
    let dir = ensure(parent)?;
    write_at(&dir, name, raw, retained_limit, observe)
}
fn public_name(name: &str) -> bool {
    name.strip_suffix(".json")
        .is_some_and(|n| Hash::from_hex(n).is_ok())
}
fn inventory(dir: &File) -> Result<(usize, usize)> {
    let mut count = 0;
    let mut total = 0usize;
    for name in names_bounded(dir, MAX_FILES + 1)? {
        if name == ".lock" {
            continue;
        }
        require(public_name(&name), "unexpected queue file")?;
        let file = open_at(dir, name.as_ref(), libc::O_RDONLY | libc::O_NONBLOCK)
            .map_err(|_| "unexpected queue file")?;
        let size = file.metadata().map_err(io_error)?.len();
        require(size <= MAX_FILE as u64, "unexpected queue file")?;
        total = total
            .checked_add(size as usize)
            .ok_or("queue capacity reached; retain existing evidence")?;
        count += 1;
    }
    Ok((count, total))
}
fn receive(
    path: &Path,
    raw: &[u8],
    source: Option<String>,
    destination: Option<String>,
    limits: &Limits,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    limits.check()?;
    let (frame, _) = inspect_bytes(raw, source, destination, limits.payload, limits.frame)?;
    let dir = ensure(path)?;
    let lock = open_at(
        &dir,
        ".lock".as_ref(),
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
    )
    .map_err(|e| format!("unsafe queue lock: {e}"))?;
    require(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
        &io_error(std::io::Error::last_os_error()),
    )?;
    // Descriptor ownership releases the original OS lock on every error/return.
    let (count, total) = inventory(&dir)?;
    let name = format!("{}.json", frame.message_id.to_hex());
    let existing = open_at(&dir, name.as_ref(), libc::O_RDONLY | libc::O_NONBLOCK);
    let new = match existing {
        Ok(file) => {
            require(
                file.metadata().map_err(io_error)?.len() <= limits.frame as u64,
                "queued message ID collision",
            )?;
            let mut bytes = vec![];
            (&file)
                .take((limits.frame + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            require(bytes == raw, "queued message ID collision")?;
            file.sync_all().map_err(io_error)?;
            dir.sync_all().map_err(io_error)?;
            false
        }
        Err(e) if e.starts_with(&format!("CONTACT_STORAGE_IO:{}:", libc::ENOENT)) => {
            require(
                count < limits.files
                    && total
                        .checked_add(raw.len())
                        .is_some_and(|n| n <= limits.bytes),
                "queue capacity reached; retain existing evidence",
            )?;
            write_at(&dir, name.as_ref(), raw, None, observe)?;
            true
        }
        Err(e) => return Err(e),
    };
    Ok(
        json!({"format":FORMAT,"message_id":frame.message_id,"new":new,"size_bytes":raw.len(),"sha256":sha(raw),"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
fn execute(
    control: &[u8],
    raw: &[u8],
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<(Value, Vec<u8>)> {
    let parsed = crate::wallet_http::decode_unique_with_limit(control, CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&parsed, CONTROL)? == control,
        "noncanonical native evidence control",
    )?;
    let request: Request = serde_json::from_value(parsed).map_err(|e| e.to_string())?;
    match request {
        Request::Info => {
            require(raw.is_empty(), "unexpected evidence payload")?;
            Ok((
                json!({"format":FORMAT,"max_file":MAX_FILE,"max_files":MAX_FILES,"max_bytes":MAX_BYTES,"max_control":CONTROL,"max_frame":MAX_FRAME,"max_payload":MAX_PAYLOAD,"ledger_authority":false,"custody_acknowledgment":false}),
                vec![],
            ))
        }
        Request::Ensure { path } => {
            require(raw.is_empty(), "unexpected evidence payload")?;
            ensure(&path)?;
            Ok((
                json!({"format":FORMAT,"ensured":true,"ledger_authority":false,"custody_acknowledgment":false}),
                vec![],
            ))
        }
        Request::Read { path, limit } => {
            require(raw.is_empty(), "unexpected evidence payload")?;
            let bytes = read(&path, limit)?;
            Ok((value(&bytes), bytes))
        }
        Request::Write {
            path,
            same,
            retained_limit,
            size_bytes,
            sha256,
        } => {
            require(
                raw.len() == size_bytes && sha(raw) == sha256,
                "native evidence payload binding differs",
            )?;
            require(
                retained_limit <= MAX_FRAME,
                "native evidence retained bound",
            )?;
            write(&path, raw, same.then_some(retained_limit), observe)?;
            Ok((value(raw), vec![]))
        }
        Request::Receive {
            path,
            source,
            destination,
            limits,
            size_bytes,
            sha256,
        } => {
            require(
                raw.len() == size_bytes && sha(raw) == sha256,
                "native evidence payload binding differs",
            )?;
            Ok((
                receive(&path, raw, source, destination, &limits, observe)?,
                vec![],
            ))
        }
        Request::Carry {
            path,
            message_id,
            output,
            source,
            destination,
            limits,
        } => {
            require(raw.is_empty(), "unexpected evidence payload")?;
            limits.check()?;
            Hash::from_hex(&message_id).map_err(|_| "invalid message ID")?;
            let bytes = read(&path.join(format!("{message_id}.json")), limits.frame)?;
            let (frame, _) =
                inspect_bytes(&bytes, source, destination, limits.payload, limits.frame)?;
            require(
                frame.message_id.to_hex() == message_id,
                "queue filename differs from frame",
            )?;
            write(&output, &bytes, None, observe)?;
            Ok((value(&bytes), bytes))
        }
    }
}
/// # Safety
/// Immutable input pointers declare their complete lengths for this call.
/// Release both unchanged returned buffers once with this library's release API.
#[no_mangle]
pub unsafe extern "C" fn rld_evidence_files(
    input: *const u8,
    len: usize,
    payload: *const u8,
    size: usize,
) -> CodecOutput {
    let control_ok = !input.is_null() && len > 0 && len <= CONTROL;
    let valid = control_ok && size <= MAX_FILE && (size == 0 || !payload.is_null());
    let control = if control_ok {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let raw = if valid && size > 0 {
        unsafe { std::slice::from_raw_parts(payload, size) }
    } else {
        &[]
    };
    let checked = std::panic::catch_unwind(|| {
        require(valid, "native evidence ABI bounds differ")?;
        execute(control, raw, &mut |_| Ok(()))
    })
    .unwrap_or_else(|_| Err("native evidence panic refused".into()));
    let (result, bytes) = match checked {
        Ok((v, b)) => (Ok(v), b),
        Err(e) => (Err(e), vec![]),
    };
    CodecOutput {
        receipt: buffer(output_with(control, || result)),
        payload: buffer(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fresh() -> PathBuf {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("rld-native-evidence-{}", hex::encode(nonce)));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn every_write_refusal_retains_exact_residue_without_ack() {
        let raw = b"complete original opaque bytes";
        for point in ["zero", "partial", "written", "file", "directory"] {
            let root = fresh();
            let target = root.join("target");
            let result = write(&target, raw, None, &mut |stage| {
                if stage == point {
                    Err("injected native failure".into())
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            let expected = if point == "zero" {
                &raw[..0]
            } else if point == "partial" {
                &raw[..raw.len() / 2]
            } else {
                raw
            };
            assert_eq!(fs::read(&target).unwrap(), expected);
            assert!(write(&target, raw, None, &mut |_| Ok(())).is_err());
            if expected == raw {
                write(&target, raw, Some(MAX_FRAME), &mut |_| Ok(())).unwrap();
            } else {
                assert!(write(&target, raw, Some(MAX_FRAME), &mut |_| Ok(())).is_err());
            }
            assert_eq!(fs::read(&target).unwrap(), expected);
        }
    }
    #[test]
    fn native_crash_child() {
        let Ok(target) = std::env::var("RLD_EVIDENCE_CRASH_TARGET") else {
            return;
        };
        let point = std::env::var("RLD_EVIDENCE_CRASH_POINT").unwrap();
        let result = write(
            Path::new(&target),
            b"complete original opaque bytes",
            None,
            &mut |stage| {
                if stage == point {
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                    // Signal delivery can follow this call's return. No later
                    // IO is allowed while waiting for the requested kill.
                    loop {
                        std::thread::park();
                    }
                }
                Ok(())
            },
        );
        panic!("missing requested interruption: {result:?}");
    }
}
