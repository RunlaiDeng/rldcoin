//! Process-local descriptor ownership; no custody, signing or ledger authority.
use crate::{
    contact_crypto::{buffer, output_with, Buffer},
    contact_storage::{cstring, directory, io_error, open_at},
    require, wallet_client, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};
const FORMAT: &str = "RLD-NATIVE-CONTACT-PROCESS-LOCK-V1";
const CONTROL: usize = 8192;
const MAX_HANDLES: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum Role {
    Mesh,
    Startup,
    Service,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Mesh => ".lock",
            Self::Startup => ".startup.lock",
            Self::Service => ".regional-contact-service.lock",
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {
    Info,
    Directory {
        path: PathBuf,
    },
    Acquire {
        token: String,
        path: PathBuf,
        role: Role,
        nonblocking: bool,
    },
    Release {
        token: String,
        path: PathBuf,
        role: Role,
    },
    Usage,
}
enum State {
    Pending,
    Held(File),
    ClosingFailed,
    Closed,
}
struct Lease {
    path: PathBuf,
    role: Role,
    pid: u32,
    state: Mutex<State>,
}
type Entry = Arc<Lease>;
static TABLE: OnceLock<Mutex<BTreeMap<String, Entry>>> = OnceLock::new();
fn table() -> Result<std::sync::MutexGuard<'static, BTreeMap<String, Entry>>> {
    TABLE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "native process lock table poisoned".into())
}
fn token_check(token: &str) -> Result<()> {
    require(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native process lock token invalid",
    )
}
fn strict_directory(path: &Path) -> Result<File> {
    require(path.is_absolute(), "directory must be absolute")?;
    let mut dir = directory(Path::new("/"))?;
    for part in path.components() {
        let name = match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Prefix(_) => return Err("unsupported directory prefix".into()),
        };
        let name_c = cstring(name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let inspected = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if inspected == 0 {
            let stat = unsafe { stat.assume_init() };
            require(
                stat.st_mode & libc::S_IFMT != libc::S_IFLNK,
                "symlink directory refused",
            )?;
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(io_error(error));
            }
            if unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(io_error(error));
                }
            }
        }
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    Ok(dir)
}
struct Reservation {
    token: String,
    entry: Entry,
    armed: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut table) = table() {
                if table
                    .get(&self.token)
                    .is_some_and(|old| Arc::ptr_eq(old, &self.entry))
                {
                    table.remove(&self.token);
                }
            }
        }
    }
}
fn acquire(token: String, path: PathBuf, role: Role, nonblocking: bool) -> Result<Value> {
    token_check(&token)?;
    let entry = Arc::new(Lease {
        path: path.clone(),
        role,
        pid: std::process::id(),
        state: Mutex::new(State::Pending),
    });
    {
        let mut table = table()?;
        require(
            !table.contains_key(&token),
            "native process lock token already exists",
        )?;
        require(
            table.len() < MAX_HANDLES,
            "native process lock handle capacity reached",
        )?;
        table.insert(token.clone(), entry.clone());
    }
    let mut reservation = Reservation {
        token: token.clone(),
        entry: entry.clone(),
        armed: true,
    };
    let dir = strict_directory(&path)?;
    let file = open_at(
        &dir,
        role.name().as_ref(),
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
    )?;
    // No registry/control mutex remains held while waiting for an OS owner.
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    *entry
        .state
        .lock()
        .map_err(|_| "native process lock state poisoned")? = State::Held(file);
    reservation.armed = false;
    Ok(
        json!({"format":FORMAT,"token":token,"path":path,"role":role,"nonblocking":nonblocking,
  "acquired":true,"ledger_authority":false,"custody_acknowledgment":false}),
    )
}
fn release(token: String, path: PathBuf, role: Role) -> Result<Value> {
    token_check(&token)?;
    let entry = table()?.get(&token).cloned();
    if let Some(entry) = entry {
        require(
            entry.path == path && entry.role == role && entry.pid == std::process::id(),
            "native process lock release binding differs",
        )?;
        let mut state = entry
            .state
            .lock()
            .map_err(|_| "native process lock state poisoned")?;
        match &*state {
            State::Pending => return Err("native process lock acquisition pending".into()),
            State::ClosingFailed => {
                return Err("native process lock descriptor close uncertain".into())
            }
            State::Closed => {}
            State::Held(_) => {
                let State::Held(file) = std::mem::replace(&mut *state, State::ClosingFailed) else {
                    unreachable!()
                };
                if unsafe { libc::close(file.into_raw_fd()) } != 0 {
                    return Err(io_error(std::io::Error::last_os_error()));
                }
                *state = State::Closed;
            }
        }
        let mut table = table()?;
        if table
            .get(&token)
            .is_some_and(|old| Arc::ptr_eq(old, &entry))
        {
            table.remove(&token);
        }
    }
    Ok(
        json!({"format":FORMAT,"token":token,"path":path,"role":role,"released":true,
  "ledger_authority":false,"custody_acknowledgment":false}),
    )
}
pub(crate) fn execute(raw: &[u8]) -> Result<Value> {
    let value = crate::wallet_http::decode_unique_with_limit(raw, CONTROL)?;
    require(
        wallet_client::canonical_with_limit(&value, CONTROL)? == raw,
        "native process lock noncanonical control",
    )?;
    let request: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    match request {
        Request::Info => Ok(
            json!({"format":FORMAT,"max_handles":MAX_HANDLES,"max_control":CONTROL,
   "roles":["Mesh","Startup","Service"],"ledger_authority":false,"custody_acknowledgment":false}),
        ),
        Request::Directory { path } => {
            strict_directory(&path)?;
            Ok(
                json!({"format":FORMAT,"path":path,"ensured":true,"ledger_authority":false,"custody_acknowledgment":false}),
            )
        }
        Request::Acquire {
            token,
            path,
            role,
            nonblocking,
        } => acquire(token, path, role, nonblocking),
        Request::Release { token, path, role } => release(token, path, role),
        Request::Usage => Ok(
            json!({"format":FORMAT,"handles":table()?.len(),"ledger_authority":false,"custody_acknowledgment":false}),
        ),
    }
}
/// # Safety
/// The declared immutable readable control bytes remain valid for this call.
/// Release the unchanged buffer once with this library's existing release API.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_process_lock(input: *const u8, len: usize) -> Buffer {
    let valid = !input.is_null() && len > 0 && len <= CONTROL;
    let raw = if valid {
        unsafe { std::slice::from_raw_parts(input, len) }
    } else {
        &[]
    };
    buffer(output_with(raw, || {
        require(valid, "native process lock ABI bounds differ")?;
        execute(raw)
    }))
}
