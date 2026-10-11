//! Native listener/task ownership with one trusted bounded custody callback.
//! Callback completion is not custody, ledger acceptance, signing or value authority.
use crate::{
    contact_crypto as crypto, contact_tls as tls, require, wallet_client as files, Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, TcpListener},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    thread::{self, JoinHandle, ThreadId},
    time::{Duration, Instant},
};
const MAX_LISTENERS: usize = 64;
const MAX_WORKERS: usize = 2;
// Probe external slots, reserve, run, refusal, release; no remote input sets these.
pub(crate) type Callback = extern "C" fn(u32, u64, f64) -> i32;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    context: u64,
    host: String,
    port: u16,
}
#[derive(Default)]
struct Control {
    owner: Option<ThreadId>,
    active: BTreeMap<u64, Option<ThreadId>>,
    failed: bool,
    accepted: u64,
    completed: u64,
    refused: u64,
}
struct Listener {
    running: AtomicBool,
    prepared: Mutex<Option<(TcpListener, Arc<rustls::ServerConfig>)>>,
    control: Mutex<Control>,
    wake: Condvar,
    sleep: Mutex<()>,
    join: Mutex<Option<JoinHandle<()>>>,
    closing: Mutex<()>,
}
static LISTENERS: OnceLock<Mutex<BTreeMap<u64, Arc<Listener>>>> = OnceLock::new();
fn table() -> Result<std::sync::MutexGuard<'static, BTreeMap<u64, Arc<Listener>>>> {
    LISTENERS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "native listener table poisoned".into())
}
fn get(handle: u64) -> Result<Arc<Listener>> {
    table()?
        .get(&handle)
        .cloned()
        .ok_or("native listener handle absent".into())
}
impl Listener {
    fn control(&self) -> Result<std::sync::MutexGuard<'_, Control>> {
        self.control
            .lock()
            .map_err(|_| "native listener control poisoned".into())
    }
    fn fail(&self) {
        if let Ok(mut c) = self.control() {
            c.failed = true;
        }
        self.running.store(false, Ordering::Release);
        self.wake.notify_all();
    }
    fn wait(&self, time: Duration) -> Result<()> {
        let guard = self
            .sleep
            .lock()
            .map_err(|_| "native listener wake poisoned")?;
        let _ = self
            .wake
            .wait_timeout_while(guard, time, |_| self.running.load(Ordering::Acquire))
            .map_err(|_| "native listener wake poisoned")?;
        Ok(())
    }
    fn release(&self, callback: Callback, handle: u64, deadline: f64) {
        tls::release(handle);
        if callback(4, handle, deadline) != 1 {
            self.fail();
        }
        if let Ok(mut c) = self.control() {
            c.active.remove(&handle);
            c.completed = c.completed.saturating_add(1);
        }
        self.wake.notify_all();
    }
}
fn io_error(e: io::Error) -> String {
    format!("TLS_IO: {e}")
}
#[cfg(unix)]
fn bind(config: &Config) -> Result<TcpListener> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let ip: Ipv4Addr = config
        .host
        .parse()
        .map_err(|_| "native listener literal IPv4 required")?;
    require(
        ip.to_string() == config.host && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST,
        "native listener IPv4 invalid",
    )?;
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    require(raw >= 0, "TLS_IO: native listener socket creation refused")?;
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let one = 1i32;
    require(
        unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "TLS_IO: listener close-on-exec refused",
    )?;
    require(
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                (&one as *const i32).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        } == 0,
        "TLS_IO: native listener reuse setting refused",
    )?;
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        addr.sin_len = std::mem::size_of_val(&addr) as u8;
    }
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = config.port.to_be();
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io_error(io::Error::last_os_error()));
    }
    if unsafe { libc::listen(raw, MAX_WORKERS as i32) } != 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    let listener = TcpListener::from(fd);
    listener.set_nonblocking(true).map_err(io_error)?;
    Ok(listener)
}
fn reap(workers: &mut Vec<JoinHandle<()>>, listener: &Listener) {
    let mut n = 0;
    while n < workers.len() {
        if workers[n].is_finished() {
            if workers.swap_remove(n).join().is_err() {
                listener.fail();
            }
        } else {
            n += 1;
        }
    }
}
fn serve(
    listener: Arc<Listener>,
    socket: TcpListener,
    config: Arc<rustls::ServerConfig>,
    callback: Callback,
) {
    if let Ok(mut c) = listener.control() {
        c.owner = Some(thread::current().id());
    }
    let mut workers = Vec::with_capacity(MAX_WORKERS);
    let run = || -> Result<()> {
        while listener.running.load(Ordering::Acquire) {
            reap(&mut workers, &listener);
            // Keep only the original kernel backlog during bounded slot handoff.
            let until = Instant::now() + Duration::from_millis(200);
            while listener.running.load(Ordering::Acquire) {
                reap(&mut workers, &listener);
                let external = callback(0, 0, 0.0);
                require(
                    (0..=2).contains(&external),
                    "native listener external slot observation failed",
                )?;
                if workers.len() + (external as usize) < MAX_WORKERS || Instant::now() >= until {
                    break;
                }
                listener.wait(Duration::from_millis(5))?;
            }
            if !listener.running.load(Ordering::Acquire) {
                break;
            }
            let (socket, _) = match socket.accept() {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    use std::os::fd::AsRawFd;
                    let mut fd = libc::pollfd {
                        fd: socket.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut fd, 1, 100) } < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        return Err(io_error(io::Error::last_os_error()));
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e)),
            };
            reap(&mut workers, &listener);
            if workers.len() >= MAX_WORKERS {
                require(
                    callback(3, 0, 0.0) == 1,
                    "native listener refusal callback failed",
                )?;
                {
                    let mut control = listener.control()?;
                    control.refused = control.refused.saturating_add(1);
                }
                drop(socket);
                continue;
            }
            let deadline = crate::bft_tick_schedule::monotonic()? + 3.0;
            let handle = tls::owned_server(config.clone(), socket, deadline)?;
            listener.control()?.active.insert(handle, None);
            let admitted = callback(1, handle, deadline);
            if admitted != 1 || !listener.running.load(Ordering::Acquire) {
                listener.release(callback, handle, deadline);
                require(
                    admitted == 0 || admitted == 1,
                    "native listener reservation callback failed",
                )?;
                if admitted == 0 {
                    let mut c = listener.control()?;
                    c.refused = c.refused.saturating_add(1);
                }
                continue;
            }
            {
                let mut control = listener.control()?;
                control.accepted = control.accepted.saturating_add(1);
            }
            let owner = listener.clone();
            let task = thread::Builder::new()
                .name("rld-native-contact-worker".into())
                .spawn(move || {
                    if let Ok(mut c) = owner.control() {
                        c.active.insert(handle, Some(thread::current().id()));
                    }
                    if callback(2, handle, deadline) != 1 {
                        owner.fail();
                    }
                    owner.release(callback, handle, deadline);
                });
            match task {
                Ok(task) => workers.push(task),
                Err(e) => {
                    listener.release(callback, handle, deadline);
                    return Err(io_error(e));
                }
            }
        }
        Ok(())
    };
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
        .unwrap_or_else(|_| Err("native listener panic".into()))
        .is_err()
    {
        listener.fail();
    }
    listener.running.store(false, Ordering::Release);
    if let Ok(c) = listener.control() {
        for handle in c.active.keys() {
            tls::interrupt(*handle);
        }
    }
    for worker in workers {
        if worker.join().is_err() {
            listener.fail();
        }
    }
    drop(socket);
}
pub(crate) fn info() -> Value {
    json!({"format":"RLD-NATIVE-CONTACT-LIFECYCLE-V1","max_listeners":MAX_LISTENERS,"workers":MAX_WORKERS,"backlog":MAX_WORKERS,"local_handoff_seconds":0.2,"attempt_seconds":3,"callback_events":[0,1,2,3,4]})
}
pub(crate) fn status(handle: u64) -> Result<Value> {
    let listener = get(handle)?;
    let c = listener.control()?;
    Ok(
        json!({"running":listener.running.load(Ordering::Acquire),"failed":c.failed,"active":c.active.len(),"accepted":c.accepted,"completed":c.completed,"refused":c.refused,"authority":false}),
    )
}
pub(crate) fn close(handle: u64) -> Result<Value> {
    let listener = match table()?.get(&handle).cloned() {
        Some(value) => value,
        None => return Ok(json!({"closed":true,"failed":false,"authority":false})),
    };
    let current = thread::current().id();
    {
        let c = listener.control()?;
        require(
            c.owner != Some(current) && !c.active.values().any(|id| *id == Some(current)),
            "native listener cannot join its own callback thread",
        )?;
    }
    let _closing = listener
        .closing
        .lock()
        .map_err(|_| "native listener close poisoned")?;
    listener.running.store(false, Ordering::Release);
    listener.wake.notify_all();
    let active = listener
        .control()?
        .active
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for handle in active {
        tls::interrupt(handle);
    }
    listener
        .prepared
        .lock()
        .map_err(|_| "native listener prepared state poisoned")?
        .take();
    if let Some(task) = listener
        .join
        .lock()
        .map_err(|_| "native listener join poisoned")?
        .take()
    {
        if task.join().is_err() {
            listener.fail();
        }
    }
    let failed = listener.control()?.failed;
    table()?.remove(&handle);
    Ok(json!({"closed":true,"failed":failed,"authority":false}))
}
pub(crate) fn prepare(context: u64, host: String, port: u16) -> Result<Value> {
    let config = Config {
        context,
        host,
        port,
    };
    let context = tls::server_context(config.context)?;
    let socket = bind(&config)?;
    let address = socket.local_addr().map_err(io_error)?;
    let listener = Arc::new(Listener {
        running: AtomicBool::new(false),
        prepared: Mutex::new(Some((socket, context))),
        control: Mutex::new(Control::default()),
        wake: Condvar::new(),
        sleep: Mutex::new(()),
        join: Mutex::new(None),
        closing: Mutex::new(()),
    });
    let handle = tls::next_handle()?;
    {
        let mut table = table()?;
        require(table.len() < MAX_LISTENERS, "native listener capacity")?;
        table.insert(handle, listener);
    }
    Ok(
        json!({"handle":handle,"host":address.ip().to_string(),"port":address.port(),"format":"RLD-NATIVE-CONTACT-LIFECYCLE-V1"}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    handle: u64,
}
fn start(raw: &[u8], callback: Option<Callback>) -> Result<Value> {
    require(
        raw.len() <= 8192,
        "native listener configuration byte bound",
    )?;
    let value = crate::wallet_http::decode_unique_with_limit(raw, 8192)?;
    require(
        files::canonical_with_limit(&value, 8192)? == raw,
        "native listener noncanonical configuration",
    )?;
    let config: Start = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let callback = callback.ok_or("native listener callback absent")?;
    let listener = get(config.handle)?;
    let _closing = listener
        .closing
        .lock()
        .map_err(|_| "native listener close poisoned")?;
    let (socket, context) = listener
        .prepared
        .lock()
        .map_err(|_| "native listener prepared state poisoned")?
        .take()
        .ok_or("native listener already started or closed")?;
    listener.running.store(true, Ordering::Release);
    let owner = listener.clone();
    match thread::Builder::new()
        .name("rld-native-contact-listener".into())
        .spawn(move || serve(owner, socket, context, callback))
    {
        Ok(task) => {
            *listener
                .join
                .lock()
                .map_err(|_| "native listener join poisoned")? = Some(task);
        }
        Err(error) => {
            listener.fail();
            return Err(io_error(error));
        }
    }
    Ok(json!({"started":true,"handle":config.handle,"authority":false}))
}
/// Start one trusted in-process callback owner. No callback address appears in JSON.
///
/// # Safety
/// Input must be readable and immutable for `len` bytes throughout this call.
/// The callback must remain executable and thread-safe until ListenerClose has
/// fully joined every callback. It must not unwind across the C boundary. It may
/// call the library recursively, but must not close/join its own listener.
/// Release the exact returned buffer once through this same library's free API.
#[no_mangle]
pub unsafe extern "C" fn rld_contact_listener_start(
    input: *const u8,
    len: usize,
    callback: Option<Callback>,
) -> crypto::Buffer {
    let raw = if input.is_null() || len == 0 || len > 8192 {
        b"".as_slice()
    } else {
        unsafe { std::slice::from_raw_parts(input, len) }
    };
    crypto::buffer(crypto::output_with(raw, || start(raw, callback)))
}
