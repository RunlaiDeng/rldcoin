//! Bounded contact spool custody operations; opaque bytes are never ledger authority.
use crate::{
    contact_crypto::{buffer, output_with, Buffer},
    contact_storage::{cstring, directory, io_error, open_at, parts, unlink_at},
    require, wallet_client, Result,
};
use miniz_oxide::inflate::{
    core::{decompress, inflate_flags, DecompressorOxide},
    TINFLStatus,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, OsStr},
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
};

const FORMAT: &str = "RLD-NATIVE-CONTACT-SPOOL-V1";
const CODEC: &str = "RLD-CONTACT-SPOOL-ZLIB-V1";
const MAGIC: &[u8] = b"RLD-CONTACT-SPOOL-ZLIB-V1\0";
const HEADER: usize = MAGIC.len() + 8 + 32;
const MAX_BATCH: usize = 20 * 1024 * 1024;
const MAX_FILES: usize = 256;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL: usize = 8192;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    batch: usize,
    files: usize,
    bytes: usize,
}
impl Limits {
    fn check(&self) -> Result<()> {
        require(
            self.batch > 0
                && self.batch <= MAX_BATCH
                && self.files <= MAX_FILES
                && self.bytes <= MAX_BYTES,
            "native spool limits differ",
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Inventory {
        path: PathBuf,
        adapter: Option<String>,
        limits: Limits,
    },
    Publish {
        path: PathBuf,
        adapter: Option<String>,
        limits: Limits,
        encoded_size: usize,
        encoded_sha256: String,
        data_size: usize,
        data_sha256: String,
    },
}
fn hex_name(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn public_name(raw: &str) -> bool {
    raw.strip_suffix(".json").is_some_and(|s| hex_name(s, 64))
}
fn adapter_check(adapter: Option<&str>) -> Result<()> {
    require(
        adapter.is_none() || adapter == Some(CODEC),
        "native spool adapter differs; no fallback",
    )
}
fn pending(raw: &str) -> Option<usize> {
    let rest = raw
        .strip_prefix(".rld-spool-pending-v1-")?
        .strip_suffix(".tmp")?;
    let mut pieces = rest.split('-');
    let ident = pieces.next()?;
    let count = pieces.next()?;
    let nonce = pieces.next()?;
    if pieces.next().is_some()
        || !hex_name(ident, 64)
        || !hex_name(nonce, 32)
        || count.is_empty()
        || count.len() > 9
        || count.starts_with('0')
        || !count.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    count.parse().ok()
}
fn expanded_size(header: &[u8], encoded_size: usize, limit: usize) -> Result<usize> {
    require(
        header.len() == HEADER && header.starts_with(MAGIC),
        "spool codec version/header differs",
    )?;
    require(
        encoded_size > HEADER && encoded_size <= limit,
        "encoded spool bound exceeded",
    )?;
    let size = u64::from_be_bytes(header[MAGIC.len()..MAGIC.len() + 8].try_into().unwrap());
    require(
        size > 0 && size <= limit as u64,
        "expanded spool bound exceeded",
    )?;
    Ok(size as usize)
}
// Private, operation-local witness derived only from complete actual input bytes.
// It never crosses the ABI, survives a call, authenticates signatures or initializes a ledger.
struct Payload<'a> {
    encoded: &'a [u8],
    data: &'a [u8],
    encoded_digest: [u8; 32],
    data_digest: [u8; 32],
}
impl<'a> Payload<'a> {
    fn new(encoded: &'a [u8], data: &'a [u8]) -> Result<Self> {
        require(
            !encoded.is_empty()
                && !data.is_empty()
                && encoded.len() <= MAX_BATCH
                && data.len() <= MAX_BATCH,
            "exchange bytes exceed bound",
        )?;
        let data_digest = Sha256::digest(data).into();
        // Equality of every immutable byte, not length/digest agreement, permits
        // coalescing the identical plain input within this operation only.
        let encoded_digest = if encoded == data {
            data_digest
        } else {
            Sha256::digest(encoded).into()
        };
        Ok(Self {
            encoded,
            data,
            encoded_digest,
            data_digest,
        })
    }
}
fn decode_exact(
    encoded: &[u8],
    expected: &Payload<'_>,
    adapter: Option<&str>,
    limit: usize,
) -> Result<()> {
    adapter_check(adapter)?;
    require(
        !encoded.is_empty() && encoded.len() <= limit && expected.data.len() <= limit,
        "encoded spool bound exceeded",
    )?;
    if adapter.is_none() {
        return require(encoded == expected.data, "exchange file collision");
    }
    let size = expanded_size(encoded.get(..HEADER).unwrap_or(&[]), encoded.len(), limit)?;
    require(size == expected.data.len(), "exchange file collision")?;
    let mut raw = vec![0; size + 1];
    let mut decoder = Box::<DecompressorOxide>::default();
    let compressed = &encoded[HEADER..];
    let (status, consumed, produced) = decompress(
        &mut decoder,
        compressed,
        &mut raw,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER,
    );
    require(
        status == TINFLStatus::Done && consumed == compressed.len() && produced == size,
        "incomplete or trailing spool stream",
    )?;
    // Compare every decoded byte before reusing the independently computed
    // complete-input digest. Header/digest agreement alone cannot authorize IO.
    require(&raw[..size] == expected.data, "exchange file collision")?;
    require(
        expected.data_digest.as_slice() == &encoded[MAGIC.len() + 8..HEADER],
        "expanded spool bytes differ",
    )
}
struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
#[cfg(target_os = "macos")]
unsafe fn errno_ptr() -> *mut i32 {
    unsafe { libc::__error() }
}
#[cfg(target_os = "linux")]
unsafe fn errno_ptr() -> *mut i32 {
    unsafe { libc::__errno_location() }
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("native spool directory observation currently requires macOS or Linux");
fn names(dir: &File) -> Result<Vec<String>> {
    names_bounded(dir, MAX_FILES)
}
pub(super) fn names_bounded(dir: &File, bound: usize) -> Result<Vec<String>> {
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let pointer = unsafe { libc::fdopendir(fd) };
    if pointer.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(io_error(error));
    }
    let stream = DirectoryStream(pointer);
    unsafe {
        libc::rewinddir(stream.0);
    }
    let mut out = vec![];
    loop {
        unsafe {
            *errno_ptr() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = unsafe { *errno_ptr() };
            require(
                error == 0,
                &io_error(std::io::Error::from_raw_os_error(error)),
            )?;
            break;
        }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        require(
            out.len() < bound,
            "contact file capacity reached; preserve spool",
        )?;
        out.push(
            std::str::from_utf8(raw)
                .map_err(|_| "unsafe contact spool file")?
                .to_owned(),
        );
    }
    Ok(out)
}
fn inventory(
    dir: &File,
    adapter: Option<&str>,
    limits: &Limits,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<(Vec<String>, usize, usize)> {
    limits.check()?;
    adapter_check(adapter)?;
    let names = names(dir)?;
    require(
        names.len() <= limits.files,
        "contact file capacity reached; preserve spool",
    )?;
    let entries = names.len();
    let mut files = vec![];
    let mut total = 0;
    for name in names {
        let reservation = pending(&name);
        let size;
        if let Some(count) = reservation {
            require(
                count <= limits.batch,
                "pending contact reservation exceeds bound",
            )?;
            observe("pending-observation")?;
            let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
            let name_c = cstring(OsStr::new(&name))?;
            if unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    name_c.as_ptr(),
                    info.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(io_error(error));
                }
            } else {
                let info = unsafe { info.assume_init() };
                require(
                    (info.st_mode & libc::S_IFMT) == libc::S_IFREG
                        && info.st_size >= 0
                        && info.st_size as u64 <= count as u64,
                    "unsafe or oversized pending contact spool file",
                )?;
            }
            size = count;
        } else {
            require(public_name(&name), "unsafe contact spool file")?;
            let mut file = open_at(dir, OsStr::new(&name), libc::O_RDONLY)?;
            let length = file.metadata().map_err(io_error)?.len();
            require(
                length <= limits.bytes as u64,
                "contact byte capacity reached; preserve spool",
            )?;
            let mut charged = length as usize;
            if adapter.is_some() {
                let mut header = vec![0; HEADER];
                file.read_exact(&mut header)
                    .map_err(|_| "spool codec version/header differs")?;
                charged = charged.max(expanded_size(&header, charged, limits.batch)?);
            }
            size = charged;
            files.push(name);
        }
        total += size;
        require(
            total <= limits.bytes,
            "contact byte capacity reached; preserve spool",
        )?;
    }
    files.sort();
    Ok((files, total, entries))
}
fn retain(
    dir: &File,
    name: &OsStr,
    payload: &Payload<'_>,
    adapter: Option<&str>,
    limits: &Limits,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<()> {
    let mut file = open_at(dir, name, libc::O_RDONLY)?;
    require(
        file.metadata().map_err(io_error)?.len() <= limits.batch as u64,
        "encoded spool bound exceeded",
    )?;
    let mut encoded = vec![];
    (&mut file)
        .take(limits.batch as u64 + 1)
        .read_to_end(&mut encoded)
        .map_err(io_error)?;
    decode_exact(&encoded, payload, adapter, limits.batch)?;
    observe("existing-sync")?;
    file.sync_all().map_err(io_error)?;
    dir.sync_all().map_err(io_error)
}
fn publish_bound(
    path: &Path,
    payload: &Payload<'_>,
    adapter: Option<&str>,
    limits: &Limits,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    let encoded = payload.encoded;
    let data = payload.data;
    limits.check()?;
    adapter_check(adapter)?;
    let (parent, name) = parts(path)?;
    let name_text =
        std::str::from_utf8(name.as_bytes()).map_err(|_| "unsafe contact spool target")?;
    require(public_name(name_text), "unsafe contact spool target")?;
    decode_exact(encoded, payload, adapter, limits.batch)?;
    let dir = directory(parent)?;
    let (_, total, entries) = inventory(&dir, adapter, limits, observe)?;
    let exists = unsafe {
        libc::faccessat(
            dir.as_raw_fd(),
            cstring(name)?.as_ptr(),
            libc::F_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0;
    if exists {
        retain(&dir, name, payload, adapter, limits, observe)?;
    } else {
        let reservation = data.len().max(encoded.len());
        require(
            entries + 2 <= limits.files && total + 2 * reservation <= limits.bytes,
            "contact capacity reached; retain queued evidence",
        )?;
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let temporary = format!(
            ".rld-spool-pending-v1-{}-{}-{}.tmp",
            &name_text[..64],
            reservation,
            hex::encode(nonce)
        );
        observe("before-create")?;
        let mut file = open_at(
            &dir,
            OsStr::new(&temporary),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        observe("zero")?;
        let half = encoded.len() / 2;
        file.write_all(&encoded[..half]).map_err(io_error)?;
        observe("partial")?;
        file.write_all(&encoded[half..]).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        observe("file")?;
        dir.sync_all().map_err(io_error)?;
        observe("pending-dir")?;
        observe("before-link")?;
        if unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                cstring(OsStr::new(&temporary))?.as_ptr(),
                dir.as_raw_fd(),
                cstring(name)?.as_ptr(),
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(io_error(error));
            }
            retain(&dir, name, payload, adapter, limits, observe)?;
        } else {
            observe("public")?;
            // Do not reopen the public name: a recipient may consume it now.
            dir.sync_all().map_err(io_error)?;
            observe("public-dir")?;
        }
        observe("before-unlink")?;
        unlink_at(&dir, &cstring(OsStr::new(&temporary))?)?;
        observe("cleanup")?;
        observe("cleanup-dir")?;
        dir.sync_all().map_err(io_error)?;
        // Any earlier failure deliberately retained the whole staging residue.
    }
    Ok(
        json!({"format":FORMAT,"encoded_size":encoded.len(),"encoded_sha256":hex::encode(payload.encoded_digest),"data_size":data.len(),"data_sha256":hex::encode(payload.data_digest),"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
fn execute(control: &[u8], encoded: &[u8], data: &[u8]) -> Result<Value> {
    let value = crate::wallet_http::decode_unique_with_limit(control, MAX_CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&value, MAX_CONTROL)? == control,
        "native spool noncanonical control",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    match request {
        Request::Info => {
            require(
                encoded.is_empty() && data.is_empty(),
                "native spool unexpected payload",
            )?;
            Ok(
                json!({"format":FORMAT,"codec":CODEC,"max_batch":MAX_BATCH,"max_files":MAX_FILES,"max_bytes":MAX_BYTES,"max_control":MAX_CONTROL,"ledger_authority":false,"custody_acknowledgment":false}),
            )
        }
        Request::Inventory {
            path,
            adapter,
            limits,
        } => {
            require(
                encoded.is_empty() && data.is_empty() && path.is_absolute(),
                "native spool inventory control differs",
            )?;
            let dir = directory(&path)?;
            let (files, total, entries) =
                inventory(&dir, adapter.as_deref(), &limits, &mut |_| Ok(()))?;
            Ok(
                json!({"format":FORMAT,"files":files,"total":total,"entries":entries,"ledger_authority":false,"custody_acknowledgment":false}),
            )
        }
        Request::Publish {
            path,
            adapter,
            limits,
            encoded_size,
            encoded_sha256,
            data_size,
            data_sha256,
        } => {
            let payload = Payload::new(encoded, data)?;
            require(
                encoded_size == encoded.len()
                    && encoded_sha256 == hex::encode(payload.encoded_digest)
                    && data_size == data.len()
                    && data_sha256 == hex::encode(payload.data_digest),
                "native spool payload binding differs",
            )?;
            publish_bound(
                &path,
                &payload,
                adapter.as_deref(),
                &limits,
                &mut |_| Ok(()),
            )
        }
    }
}
/// # Safety
/// Every nonnull pointer declares immutable readable bytes for this call. Null
/// payloads are permitted only for zero length. Free the returned exact buffer
/// once with rld_contact_crypto_free. No control accepts executable addresses.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_spool(
    input: *const u8,
    len: usize,
    encoded: *const u8,
    encoded_len: usize,
    data: *const u8,
    data_len: usize,
) -> Buffer {
    let control_ok = !input.is_null() && len > 0 && len <= MAX_CONTROL;
    let valid = control_ok
        && encoded_len <= MAX_BATCH
        && data_len <= MAX_BATCH
        && (encoded_len == 0 || !encoded.is_null())
        && (data_len == 0 || !data.is_null());
    let control = if control_ok {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let encoded = if valid && encoded_len > 0 {
        unsafe { std::slice::from_raw_parts(encoded, encoded_len) }
    } else {
        &[]
    };
    let data = if valid && data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };
    buffer(output_with(control, || {
        require(valid, "native spool ABI bounds differ")?;
        execute(control, encoded, data)
    }))
}

#[cfg(test)]
fn publish(
    path: &Path,
    encoded: &[u8],
    data: &[u8],
    adapter: Option<&str>,
    limits: &Limits,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    publish_bound(
        path,
        &Payload::new(encoded, data)?,
        adapter,
        limits,
        observe,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fresh_root() -> PathBuf {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("rld-native-spool-{}", hex::encode(nonce)));
        std::fs::create_dir(&root).unwrap();
        root
    }
    fn limits() -> Limits {
        Limits {
            batch: MAX_BATCH,
            files: MAX_FILES,
            bytes: MAX_BYTES,
        }
    }
    fn public_target(root: &Path) -> PathBuf {
        root.join(format!("{}.json", "a".repeat(64)))
    }
    #[test]
    fn publication_failures_retain_residue_and_never_replace() {
        for (point, count, public) in [
            ("before-create", 0, false),
            ("zero", 1, false),
            ("partial", 1, false),
            ("file", 1, false),
            ("pending-dir", 1, false),
            ("before-link", 1, false),
            ("public", 2, true),
            ("public-dir", 2, true),
            ("before-unlink", 2, true),
            ("cleanup-dir", 1, true),
        ] {
            let root = fresh_root();
            let target = public_target(&root);
            let raw = b"complete original bytes";
            let err = publish(&target, raw, raw, None, &limits(), &mut |stage| {
                if stage == point {
                    Err("injected failure".into())
                } else {
                    Ok(())
                }
            });
            assert!(err.is_err(), "{point}");
            assert_eq!(std::fs::read_dir(&root).unwrap().count(), count, "{point}");
            assert_eq!(target.exists(), public, "{point}");
            if public {
                assert_eq!(std::fs::read(&target).unwrap(), raw);
            }
        }
    }
    #[test]
    fn consumed_name_and_competing_duplicates_preserve_complete_bytes() {
        let raw = b"complete original bytes";
        let root = fresh_root();
        let target = public_target(&root);
        publish(&target, raw, raw, None, &limits(), &mut |stage| {
            if stage == "public" {
                assert_eq!(std::fs::read(&target).unwrap(), raw);
                std::fs::remove_file(&target).unwrap();
                directory(&root).unwrap().sync_all().unwrap();
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        for same in [true, false] {
            let root = fresh_root();
            let target = public_target(&root);
            let result = publish(&target, raw, raw, None, &limits(), &mut |stage| {
                if stage == "before-link" {
                    std::fs::write(
                        &target,
                        if same {
                            raw.as_slice()
                        } else {
                            b"different bytes"
                        },
                    )
                    .unwrap();
                }
                Ok(())
            });
            assert_eq!(result.is_ok(), same);
            assert_eq!(
                std::fs::read_dir(&root).unwrap().count(),
                if same { 1 } else { 2 }
            );
            assert_eq!(
                std::fs::read(&target).unwrap(),
                if same {
                    raw.as_slice()
                } else {
                    b"different bytes"
                }
            );
        }
    }
    #[test]
    fn disappeared_pending_still_charged_and_repeat_inventory_reads_actual_directory() {
        let root = fresh_root();
        let dir = directory(&root).unwrap();
        let name = format!(
            ".rld-spool-pending-v1-{}-123-{}.tmp",
            "a".repeat(64),
            "b".repeat(32)
        );
        std::fs::write(root.join(&name), b"partial").unwrap();
        let observed = inventory(&dir, None, &limits(), &mut |stage| {
            if stage == "pending-observation" {
                std::fs::remove_file(root.join(&name)).unwrap();
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(observed, (vec![], 123, 1));
        assert_eq!(
            inventory(&dir, None, &limits(), &mut |_| Ok(())).unwrap(),
            (vec![], 0, 0)
        );
    }
    #[test]
    fn crash_child() {
        let Ok(target) = std::env::var("RLD_SPOOL_CRASH_TARGET") else {
            return;
        };
        let point = std::env::var("RLD_SPOOL_CRASH_POINT").unwrap();
        let result = publish(
            Path::new(&target),
            b"complete original bytes",
            b"complete original bytes",
            None,
            &limits(),
            &mut |stage| {
                if stage == point {
                    unsafe {
                        libc::raise(libc::SIGKILL);
                    }
                    return Err("SIGKILL unexpectedly returned".into());
                }
                Ok(())
            },
        );
        panic!("crash boundary not reached: {result:?}");
    }
}
