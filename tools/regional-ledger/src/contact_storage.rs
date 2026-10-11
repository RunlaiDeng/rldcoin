//! Exact byte publication and synchronization, never authentication or ledger authority.
use crate::{
    contact_crypto::{buffer, output_with, Buffer},
    require, wallet_client, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
};

const FORMAT: &str = "RLD-NATIVE-CONTACT-STORAGE-V1";
const MAX_FILE: usize = 64 * 1024 * 1024;
const MAX_PATHS: usize = 2 * (256 + 4);
const MAX_CONTROL: usize = 3 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    ArchiveWrite {
        path: PathBuf,
        size_bytes: usize,
        sha256: String,
    },
    AtomicWrite {
        path: PathBuf,
        size_bytes: usize,
        sha256: String,
        limit: usize,
    },
    SyncMany {
        paths: Vec<PathBuf>,
    },
}
fn io_error(error: std::io::Error) -> String {
    format!(
        "CONTACT_STORAGE_IO:{}:{}",
        error.raw_os_error().unwrap_or(libc::EIO),
        error
    )
}
fn cstring(path: &std::ffi::OsStr) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_bytes()).map_err(|_| "contact storage NUL path".into())
}
fn directory(path: &Path) -> Result<File> {
    let name = cstring(path.as_os_str())?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn parts(path: &Path) -> Result<(&Path, &std::ffi::OsStr)> {
    require(path.is_absolute(), "contact storage path must be absolute")?;
    let parent = path.parent().ok_or("contact storage parent absent")?;
    let name = path.file_name().ok_or("contact storage file name absent")?;
    require(
        parent != path && name.len() <= 255,
        "contact storage file name bound",
    )?;
    Ok((parent, name))
}
fn open_at(dir: &File, name: &std::ffi::OsStr, flags: i32) -> Result<File> {
    let name = cstring(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    require(
        file.metadata().map_err(io_error)?.is_file(),
        "contact storage regular file required",
    )?;
    Ok(file)
}
fn sync(
    file: &File,
    stage: &'static str,
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<()> {
    observe(stage)?;
    file.sync_all().map_err(io_error)
}
fn unlink_at(dir: &File, name: &CString) -> Result<()> {
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}
fn atomic(
    path: &Path,
    raw: &[u8],
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    require(raw.len() <= MAX_FILE, "contact state capacity")?;
    let (parent, name) = parts(path)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(io_error)?;
    let dir = directory(parent)?;
    let mut random = [0; 16];
    getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
    let temporary = format!(".write-{}", hex::encode(random));
    let temporary_c = cstring(temporary.as_ref())?;
    let target_c = cstring(name)?;
    let mut file = open_at(
        &dir,
        temporary.as_ref(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    let mut renamed = false;
    let operation = (|| {
        observe("state-write")?;
        file.write_all(raw).map_err(io_error)?;
        sync(&file, "state-file-sync", observe)?;
        sync(&dir, "state-staging-directory-sync", observe)?;
        observe("state-prepared")?;
        observe("state-replace")?;
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temporary_c.as_ptr(),
                dir.as_raw_fd(),
                target_c.as_ptr(),
            )
        } != 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        renamed = true;
        observe("state-replaced")?;
        sync(&dir, "state-publication-directory-sync", observe)?;
        Ok(
            json!({"format":FORMAT,"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw)),
            "ledger_authority":false,"custody_acknowledgment":false}),
        )
    })();
    // Only this call's disposable staging name can be removed. A target already
    // replaced is never rolled back on a lost result or failed directory sync.
    let cleanup = if renamed {
        Ok(())
    } else {
        (|| {
            observe("state-cleanup")?;
            unlink_at(&dir, &temporary_c)
        })()
    };
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; cleanup: {cleanup}")),
    }
}
fn archive(
    path: &Path,
    raw: &[u8],
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    require(raw.len() <= MAX_FILE, "contact archive capacity")?;
    let (parent, name) = parts(path)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(io_error)?;
    let dir = directory(parent)?;
    let mut random = [0; 32];
    getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
    let temporary = format!(".archive-write-{}", hex::encode(random));
    let temporary_c = cstring(temporary.as_ref())?;
    let target_c = cstring(name)?;
    let mut file = open_at(
        &dir,
        temporary.as_ref(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    let operation = (|| {
        observe("write")?;
        file.write_all(raw).map_err(io_error)?;
        sync(&file, "staging-file-sync", observe)?;
        sync(&dir, "staging-directory-sync", observe)?;
        observe("prepared")?;
        observe("link")?;
        if unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                temporary_c.as_ptr(),
                dir.as_raw_fd(),
                target_c.as_ptr(),
                0,
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(io_error(error));
            }
            let retained = open_at(&dir, name, libc::O_RDONLY)?;
            require(
                retained.metadata().map_err(io_error)?.len() <= MAX_FILE as u64,
                "contact archive retained capacity",
            )?;
            let mut complete = Vec::new();
            retained
                .take((MAX_FILE + 1) as u64)
                .read_to_end(&mut complete)
                .map_err(io_error)?;
            require(complete == raw, "existing archive differs")?;
        }
        observe("published")?;
        let retained = open_at(&dir, name, libc::O_RDONLY)?;
        sync(&retained, "retained-file-sync", observe)?;
        sync(&dir, "retained-directory-sync", observe)?;
        Ok(
            json!({"format":FORMAT,"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw)),
            "ledger_authority":false,"custody_acknowledgment":false}),
        )
    })();
    // Never remove the published target. Incomplete native publication cannot
    // advance the separately authenticated index or acknowledge a received job.
    let cleanup = (|| {
        observe("cleanup")?;
        unlink_at(&dir, &temporary_c)?;
        sync(&dir, "cleanup-directory-sync", observe)
    })();
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; cleanup: {cleanup}")),
    }
}
fn sync_many(
    paths: &[PathBuf],
    observe: &mut dyn FnMut(&'static str) -> Result<()>,
) -> Result<Value> {
    require(
        paths.len() <= MAX_PATHS,
        "retained custody sync capacity exceeded",
    )?;
    let mut seen = BTreeSet::new();
    let mut directories = BTreeMap::new();
    for path in paths {
        if !seen.insert(path.clone()) {
            continue;
        }
        let (parent, name) = parts(path)?;
        if !directories.contains_key(parent) {
            directories.insert(parent.to_path_buf(), directory(parent)?);
        }
        let dir = directories
            .get(parent)
            .ok_or("contact sync parent absent")?;
        let file = open_at(dir, name, libc::O_RDONLY)?;
        sync(&file, "retained-file-sync", observe)?;
    }
    for dir in directories.values() {
        sync(dir, "retained-directory-sync", observe)?;
    }
    Ok(
        json!({"format":FORMAT,"files_synced":seen.len(),"directories_synced":directories.len(),
        "ledger_authority":false,"custody_acknowledgment":false}),
    )
}
fn execute(control: &[u8], payload: &[u8]) -> Result<Value> {
    require(
        !control.is_empty() && control.len() <= MAX_CONTROL && payload.len() <= MAX_FILE,
        "contact storage ABI capacity",
    )?;
    let value = crate::wallet_http::decode_unique_with_limit(control, MAX_CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&value, MAX_CONTROL)? == control,
        "contact storage canonical control",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let mut observe = |_| Ok(());
    match request {
        Request::Info => {
            require(payload.is_empty(), "contact storage unexpected payload")?;
            Ok(
                json!({"format":FORMAT,"max_file":MAX_FILE,"max_paths":MAX_PATHS,"max_control":MAX_CONTROL,"atomic_write":true,
                "ledger_authority":false,"custody_acknowledgment":false}),
            )
        }
        Request::ArchiveWrite {
            path,
            size_bytes,
            sha256,
        } => {
            require(
                size_bytes == payload.len() && sha256 == hex::encode(Sha256::digest(payload)),
                "contact storage payload binding differs",
            )?;
            archive(&path, payload, &mut observe)
        }
        Request::AtomicWrite {
            path,
            size_bytes,
            sha256,
            limit,
        } => {
            require(
                limit <= MAX_FILE && payload.len() <= limit,
                "contact state capacity",
            )?;
            require(
                size_bytes == payload.len() && sha256 == hex::encode(Sha256::digest(payload)),
                "contact storage payload binding differs",
            )?;
            atomic(&path, payload, &mut observe)
        }
        Request::SyncMany { paths } => {
            require(payload.is_empty(), "contact storage unexpected payload")?;
            sync_many(&paths, &mut observe)
        }
    }
}
/// Execute bounded file operations; complete bytes remain distinct from authority.
///
/// # Safety
/// Each nonnull input points to its declared readable immutable bytes for the
/// whole call. A null pointer is valid only with zero length. Free the returned
/// buffer exactly once through rld_contact_crypto_free, without changing it.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_storage(
    input: *const u8,
    len: usize,
    payload: *const u8,
    payload_len: usize,
) -> Buffer {
    let valid_control = len > 0 && len <= MAX_CONTROL && !input.is_null();
    let valid =
        valid_control && payload_len <= MAX_FILE && (payload_len == 0 || !payload.is_null());
    let control = if valid_control {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    let bytes = if valid && payload_len > 0 {
        unsafe { std::slice::from_raw_parts(payload, payload_len) }
    } else {
        &[]
    };
    buffer(output_with(control, || {
        require(valid, "contact storage ABI input invalid")?;
        execute(control, bytes)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> PathBuf {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let base = std::env::var_os("RLD_STORAGE_TEST_DIRECTORY")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let root = base.join(format!("rld-native-storage-{}", hex::encode(random)));
        fs::create_dir_all(&root).unwrap();
        root
    }
    #[test]
    fn exact_existing_bytes_never_rewrite_or_replace() {
        use std::os::unix::fs::MetadataExt;
        let root = fixture();
        let path = root.join("a.json");
        let raw = b"{\"body\":\"complete\"}";
        archive(&path, raw, &mut |_| Ok(())).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        archive(&path, raw, &mut |_| Ok(())).unwrap();
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert!(archive(&path, b"altered", &mut |_| Ok(()))
            .unwrap_err()
            .contains("existing archive differs"));
        assert_eq!(fs::read(&path).unwrap(), raw);
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }
    #[test]
    fn write_link_and_every_sync_failure_refuse_success() {
        for failed in [
            "write",
            "staging-file-sync",
            "staging-directory-sync",
            "link",
            "retained-file-sync",
            "retained-directory-sync",
            "cleanup",
            "cleanup-directory-sync",
        ] {
            let root = fixture();
            let path = root.join("retained.json");
            let raw = b"exact complete bytes";
            let result = archive(&path, raw, &mut |stage| {
                if stage == failed {
                    Err(io_error(std::io::Error::from_raw_os_error(libc::EIO)))
                } else {
                    Ok(())
                }
            });
            assert!(result.unwrap_err().starts_with("CONTACT_STORAGE_IO:5:"));
            if path.exists() {
                assert_eq!(fs::read(&path).unwrap(), raw);
            }
            if [
                "write",
                "staging-file-sync",
                "staging-directory-sync",
                "link",
            ]
            .contains(&failed)
            {
                assert!(!path.exists());
            }
            let residues = fs::read_dir(&root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".archive-write-")
                })
                .count();
            assert_eq!(residues, usize::from(failed == "cleanup"));
        }
    }
    #[test]
    fn sync_order_deduplicates_only_within_call() {
        let root = fixture();
        let a = root.join("a");
        let b = root.join("b");
        fs::write(&a, b"a").unwrap();
        fs::write(&b, b"b").unwrap();
        let mut seen = Vec::new();
        let mut observe = |stage| {
            seen.push(stage);
            Ok(())
        };
        sync_many(&[a.clone(), b.clone(), a.clone()], &mut observe).unwrap();
        sync_many(&[a, b], &mut observe).unwrap();
        assert_eq!(
            seen,
            vec![
                "retained-file-sync",
                "retained-file-sync",
                "retained-directory-sync",
                "retained-file-sync",
                "retained-file-sync",
                "retained-directory-sync"
            ]
        );
        assert!(
            sync_many(&vec![root.join("absent"); MAX_PATHS + 1], &mut |_| panic!(
                "capacity checked before I/O"
            ))
            .unwrap_err()
            .contains("capacity")
        );
    }
    #[test]
    fn sync_failure_preserves_files_and_later_retry_repeats_sync() {
        let root = fixture();
        let path = root.join("a");
        fs::write(&path, b"already authenticated separately").unwrap();
        let mut seen = Vec::new();
        assert!(sync_many(std::slice::from_ref(&path), &mut |stage| {
            seen.push(stage);
            if stage == "retained-directory-sync" {
                Err("injected directory failure".into())
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(seen, vec!["retained-file-sync", "retained-directory-sync"]);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"already authenticated separately"
        );
        sync_many(&[path], &mut |_| Ok(())).unwrap();
    }
    #[test]
    fn symlink_file_and_directory_refuse_without_mutation() {
        use std::os::unix::fs::symlink;
        let root = fixture();
        let original = root.join("original");
        fs::write(&original, b"retained").unwrap();
        let link = root.join("link");
        symlink(&original, &link).unwrap();
        assert!(archive(&link, b"retained", &mut |_| Ok(())).is_err());
        assert!(sync_many(&[link], &mut |_| Ok(())).is_err());
        let directory_link = root.join("directory-link");
        symlink(&root, &directory_link).unwrap();
        assert!(archive(&directory_link.join("new"), b"refused", &mut |_| Ok(())).is_err());
        assert_eq!(fs::read(original).unwrap(), b"retained");
        assert!(!root.join("new").exists());
    }
    #[test]
    fn control_binds_actual_payload_and_declared_capacity() {
        let root = fixture();
        let path = root.join("a");
        let raw = b"bytes";
        let value = json!({"ArchiveWrite":{"path":path,"size_bytes":raw.len(),"sha256":hex::encode(Sha256::digest(raw))}});
        let control = wallet_client::canonical_with_limit(&value, MAX_CONTROL).unwrap();
        assert!(execute(&control, b"wrong").unwrap_err().contains("binding"));
        assert!(!path.exists());
        assert!(execute(b"\"Info\"", b"unexpected").is_err());
        assert!(execute(b" {\"SyncMany\":{\"paths\":[]}}", &[]).is_err());
        execute(&control, raw).unwrap();
        assert_eq!(fs::read(path).unwrap(), raw);
    }
    #[test]
    fn crash_child() {
        let Some(path) = std::env::var_os("RLD_STORAGE_CRASH_TARGET") else {
            return;
        };
        let point = std::env::var("RLD_STORAGE_CRASH_POINT").unwrap();
        archive(
            Path::new(&path),
            b"complete crash-bound bytes",
            &mut |stage| {
                if stage == point {
                    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                    panic!("SIGKILL returned");
                }
                Ok(())
            },
        )
        .unwrap();
        panic!("crash point not reached");
    }
    #[test]
    fn process_interrupt_retains_exact_prepared_and_published_residue() {
        use std::os::unix::process::ExitStatusExt;
        for point in ["prepared", "published"] {
            let root = fixture();
            let target = root.join("a.json");
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "contact_storage::tests::crash_child",
                    "--nocapture",
                ])
                .env("RLD_STORAGE_CRASH_TARGET", &target)
                .env("RLD_STORAGE_CRASH_POINT", point)
                .output()
                .unwrap();
            assert_eq!(result.status.signal(), Some(libc::SIGKILL));
            let files: Vec<_> = fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(files.len(), if point == "prepared" { 1 } else { 2 });
            for path in &files {
                assert_eq!(fs::read(path).unwrap(), b"complete crash-bound bytes");
            }
            assert_eq!(target.exists(), point == "published");
            // Observe retained residue only. Do not clean or republish it as a pass.
        }
    }
    #[test]
    fn atomic_publication_order_and_old_bytes_before_replace() {
        let root = fixture();
        let path = root.join("state.json");
        fs::write(&path, b"old signed bytes").unwrap();
        let mut stages = Vec::new();
        atomic(&path, b"new complete signed bytes", &mut |stage| {
            stages.push(stage);
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new complete signed bytes");
        assert_eq!(
            stages,
            vec![
                "state-write",
                "state-file-sync",
                "state-staging-directory-sync",
                "state-prepared",
                "state-replace",
                "state-replaced",
                "state-publication-directory-sync"
            ]
        );
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }
    #[test]
    fn atomic_write_replace_sync_failures_never_acknowledge_or_roll_back_installed_bytes() {
        for failed in [
            "state-write",
            "state-file-sync",
            "state-staging-directory-sync",
            "state-replace",
            "state-publication-directory-sync",
        ] {
            let root = fixture();
            let path = root.join("state.json");
            fs::write(&path, b"old").unwrap();
            let result = atomic(&path, b"new", &mut |stage| {
                if stage == failed {
                    Err(io_error(std::io::Error::from_raw_os_error(libc::EIO)))
                } else {
                    Ok(())
                }
            });
            assert!(result.unwrap_err().starts_with("CONTACT_STORAGE_IO:5:"));
            assert_eq!(
                fs::read(&path).unwrap(),
                if failed == "state-publication-directory-sync" {
                    b"new"
                } else {
                    b"old"
                }
            );
            assert_eq!(fs::read_dir(root).unwrap().count(), 1);
        }
        let root = fixture();
        let path = root.join("state.json");
        fs::write(&path, b"old").unwrap();
        let error = atomic(&path, b"new", &mut |stage| {
            if stage == "state-write" || stage == "state-cleanup" {
                Err(format!("injected {stage}"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.contains("injected state-write; cleanup: injected state-cleanup"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(fs::read_dir(root).unwrap().count(), 2);
    }
    #[test]
    fn atomic_limit_and_actual_payload_binding_precede_all_file_operations() {
        let root = fixture();
        let path = root.join("state.json");
        for (limit, payload, declared) in [
            (2, b"new".as_slice(), 3),
            (MAX_FILE + 1, b"new".as_slice(), 3),
            (3, b"bad".as_slice(), 3),
            (3, b"new".as_slice(), 2),
        ] {
            let request = json!({"AtomicWrite":{"path":path,"size_bytes":declared,"sha256":hex::encode(Sha256::digest(b"new")),"limit":limit}});
            let control = wallet_client::canonical_with_limit(&request, MAX_CONTROL).unwrap();
            assert!(execute(&control, payload).is_err());
            assert!(!path.exists());
        }
    }
    #[test]
    fn atomic_crash_child() {
        let Some(path) = std::env::var_os("RLD_ATOMIC_CRASH_TARGET") else {
            return;
        };
        let point = std::env::var("RLD_ATOMIC_CRASH_POINT").unwrap();
        let payload = match std::env::var_os("RLD_ATOMIC_CRASH_PAYLOAD") {
            Some(file) => {
                crate::wallet_client::private_read_with_limit(Path::new(&file), MAX_FILE).unwrap()
            }
            None => b"new complete bytes".to_vec(),
        };
        atomic(Path::new(&path), &payload, &mut |stage| {
            if stage == point {
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
                panic!("SIGKILL returned");
            }
            Ok(())
        })
        .unwrap();
        panic!("atomic crash point not reached");
    }
    #[test]
    fn atomic_process_interrupt_before_and_after_replace_preserves_exact_observed_state() {
        use std::os::unix::process::ExitStatusExt;
        for point in ["state-prepared", "state-replaced"] {
            let root = fixture();
            let path = root.join("state.json");
            fs::write(&path, b"old complete bytes").unwrap();
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "contact_storage::tests::atomic_crash_child",
                    "--nocapture",
                ])
                .env("RLD_ATOMIC_CRASH_TARGET", &path)
                .env("RLD_ATOMIC_CRASH_POINT", point)
                .output()
                .unwrap();
            assert_eq!(result.status.signal(), Some(libc::SIGKILL));
            assert_eq!(
                fs::read(&path).unwrap(),
                if point == "state-prepared" {
                    b"old complete bytes"
                } else {
                    b"new complete bytes"
                }
            );
            let files: Vec<_> = fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(files.len(), if point == "state-prepared" { 2 } else { 1 });
            for entry in files {
                if entry != path {
                    assert_eq!(fs::read(entry).unwrap(), b"new complete bytes");
                }
            }
        }
    }
}
