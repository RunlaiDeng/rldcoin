//! Bounded one-request loopback HTTP carriage. Browser bytes grant no value rights.
use crate::{
    require,
    wallet_app::{App, Options},
    wallet_client, Result, MAX_BYTES,
};
use serde::{
    de::{self, Deserialize, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use serde_json::{json, Value};
use std::{
    fmt,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_HEADERS: usize = 8192;
const MAX_REQUEST: usize = 2 * 1024 * 1024;
const SESSION_SECONDS: u64 = 3600;
static STOP: AtomicBool = AtomicBool::new(false);

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("duplicate-free JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                require(v.is_finite(), "nonfinite JSON").map_err(E::custom)?;
                Ok(Unique(json!(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(json!(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<Unique>()? {
                    values.push(v.0);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                    values.insert(key, map.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        d.deserialize_any(UniqueVisitor)
    }
}

pub(crate) fn decode_unique(raw: &[u8]) -> Result<Value> {
    decode_unique_with_limit(raw, MAX_BYTES)
}

#[cfg(test)]
pub(crate) mod decode_cost {
    use super::*;
    thread_local! {
        static EXACT: std::cell::RefCell<Option<(Vec<u8>, usize)>> = const { std::cell::RefCell::new(None) };
    }
    pub(crate) fn begin(raw: &[u8]) -> Result<()> {
        require(
            !raw.is_empty() && raw.len() <= crate::contact::MAX_PAYLOAD,
            "decode observation payload bound",
        )?;
        EXACT.with(|slot| {
            let mut slot = slot.borrow_mut();
            require(slot.is_none(), "decode observation already active")?;
            *slot = Some((raw.to_vec(), 0));
            Ok(())
        })
    }
    pub(crate) fn take() -> usize {
        EXACT.with(|slot| slot.borrow_mut().take().map_or(0, |(_, calls)| calls))
    }
    pub(super) fn record(raw: &[u8]) -> Result<()> {
        EXACT.with(|slot| {
            if let Some((expected, calls)) = slot.borrow_mut().as_mut() {
                if expected.as_slice() == raw {
                    *calls = calls
                        .checked_add(1)
                        .ok_or("decode observation count overflow")?;
                }
            }
            Ok(())
        })
    }
}

pub(crate) fn decode_unique_with_limit(raw: &[u8], limit: usize) -> Result<Value> {
    #[cfg(test)]
    decode_cost::record(raw)?;
    require(raw.len() <= limit, "JSON byte bound")?;
    serde_json::from_slice::<Unique>(raw)
        .map(|v| v.0)
        .map_err(|e| e.to_string())
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Request {
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn unique(&self, name: &str) -> Result<&str> {
        let values = self.all(name);
        require(values.len() == 1, "missing or duplicate HTTP header")?;
        Ok(values[0])
    }
}

fn remaining(start: Instant) -> Result<Duration> {
    Duration::from_secs(3)
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or("local request input deadline".into())
}

fn read_request(stream: &mut TcpStream) -> Result<Request> {
    let start = Instant::now();
    let mut bytes = Vec::new();
    // Read only through the header boundary. One total input deadline applies
    // even when an adversarial client trickles individual bytes.
    while !bytes.ends_with(b"\r\n\r\n") {
        require(bytes.len() < MAX_HEADERS, "HTTP header byte bound")?;
        stream
            .set_read_timeout(Some(remaining(start)?))
            .map_err(|e| e.to_string())?;
        let mut byte = [0];
        require(
            stream.read(&mut byte).map_err(|e| e.to_string())? == 1,
            "incomplete HTTP headers",
        )?;
        bytes.push(byte[0]);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "HTTP header encoding")?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or("HTTP request line missing")?;
    let parts: Vec<_> = first.split(' ').collect();
    require(
        parts.len() == 3 && parts[2] == "HTTP/1.1" && matches!(parts[0], "GET" | "POST"),
        "unsupported HTTP request line",
    )?;
    let mut headers = Vec::new();
    for line in lines.take_while(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or("HTTP header missing separator")?;
        require(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
            "invalid HTTP header name",
        )?;
        require(
            value.bytes().all(|b| b == b'\t' || (32..127).contains(&b)),
            "invalid HTTP header value",
        )?;
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    let mut request = Request {
        method: parts[0].into(),
        target: parts[1].into(),
        headers,
        body: Vec::new(),
    };
    require(
        request.all("transfer-encoding").is_empty(),
        "HTTP transfer encoding refused",
    )?;
    if request.method == "POST" {
        let count = request.unique("content-length")?;
        require(
            !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()),
            "invalid HTTP content length",
        )?;
        let count: usize = count.parse().map_err(|_| "invalid HTTP content length")?;
        require(
            (1..=MAX_REQUEST).contains(&count),
            "HTTP request body bound",
        )?;
        request.body.resize(count, 0);
        let mut offset = 0;
        while offset < count {
            stream
                .set_read_timeout(Some(remaining(start)?))
                .map_err(|e| e.to_string())?;
            let read = stream
                .read(&mut request.body[offset..])
                .map_err(|e| e.to_string())?;
            require(read > 0, "incomplete HTTP request body")?;
            offset += read;
        }
    } else {
        require(
            request.all("content-length").is_empty() || request.unique("content-length")? == "0",
            "GET body refused",
        )?;
    }
    Ok(request)
}

fn constant_equal(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(left.ct_eq(right))
}

fn write_response(stream: &mut TcpStream, status: u16, kind: &str, raw: &[u8]) -> Result<()> {
    require(raw.len() <= MAX_BYTES, "response outside bound")?;
    let reason = if status == 200 {
        "OK"
    } else if status == 403 {
        "Forbidden"
    } else {
        "Conflict"
    };
    let header=format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n\r\n",raw.len());
    let started = Instant::now();
    for bytes in [header.as_bytes(), raw] {
        let mut offset = 0;
        while offset < bytes.len() {
            let timeout = Duration::from_secs(3)
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or("local response output deadline")?;
            stream
                .set_write_timeout(Some(timeout))
                .map_err(|e| e.to_string())?;
            let count = stream.write(&bytes[offset..]).map_err(|e| e.to_string())?;
            require(count > 0, "incomplete local response")?;
            offset += count;
        }
    }
    Ok(())
}

fn handle(
    stream: &mut TcpStream,
    app: &mut App,
    host: &str,
    origin: &str,
    token: &str,
    started: Instant,
) -> Result<()> {
    let request = read_request(stream)?;
    require(!STOP.load(Ordering::Relaxed), "wallet is stopping")?;
    require(request.unique("host")? == host, "invalid local host")?;
    if request.method == "GET" {
        let asset: Option<(&[u8], &str)> = match request.target.as_str() {
            "/" => Some((
                include_bytes!("../../regional-wallet/index.html"),
                "text/html; charset=utf-8",
            )),
            "/app.js" => Some((
                include_bytes!("../../regional-wallet/app.js"),
                "text/javascript; charset=utf-8",
            )),
            "/app.css" => Some((
                include_bytes!("../../regional-wallet/app.css"),
                "text/css; charset=utf-8",
            )),
            _ => None,
        };
        if let Some((bytes, kind)) = asset {
            require(bytes.len() <= 512 * 1024, "static asset bound")?;
            return write_response(stream, 200, kind, bytes);
        }
        return write_response(
            stream,
            403,
            "application/json",
            b"{\"error\":\"Local request refused\"}",
        );
    }
    require(
        request.target == "/api"
            && request.unique("origin")? == origin
            && started.elapsed().as_secs() < SESSION_SECONDS,
        "Local session is invalid or expired",
    )?;
    let fetch = request.all("sec-fetch-site");
    require(
        fetch.is_empty() || fetch.len() == 1 && matches!(fetch[0], "same-origin" | "none"),
        "invalid fetch origin",
    )?;
    require(
        constant_equal(
            request.unique("authorization")?.as_bytes(),
            format!("Bearer {token}").as_bytes(),
        ),
        "Local session is invalid or expired",
    )?;
    require(
        request.unique("content-type")? == "application/json",
        "invalid request content type",
    )?;
    let action =
        serde_json::from_value(decode_unique(&request.body)?).map_err(|e| e.to_string())?;
    require(!STOP.load(Ordering::Relaxed), "wallet is stopping")?;
    let value = app.act(action)?;
    write_response(
        stream,
        200,
        "application/json",
        &wallet_client::canonical(&value)?,
    )
}

extern "C" fn stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Signals {
    int: libc::sighandler_t,
    term: libc::sighandler_t,
}
impl Signals {
    fn install() -> Result<Self> {
        let callback = stop_signal as *const () as libc::sighandler_t;
        let int = unsafe { libc::signal(libc::SIGINT, callback) };
        require(
            int != libc::SIG_ERR,
            "wallet signal handler installation failed",
        )?;
        let term = unsafe { libc::signal(libc::SIGTERM, callback) };
        if term == libc::SIG_ERR {
            unsafe {
                libc::signal(libc::SIGINT, int);
            }
            return Err("wallet signal handler installation failed".into());
        }
        Ok(Self { int, term })
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.int);
            libc::signal(libc::SIGTERM, self.term);
        }
    }
}

pub fn serve(options: Options, port: u16) -> Result<()> {
    let mut app = App::open(options)?;
    let listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let host = listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .to_string();
    let origin = format!("http://{host}");
    let token = crate::wallet_app::random_id()?.to_hex();
    let started = Instant::now();
    STOP.store(false, Ordering::Relaxed);
    // Only the standalone CLI calls serve. Restore handlers before returning.
    let _signals = Signals::install()?;
    println!(
        "{}",
        json!({"local_wallet_url":format!("{origin}/#{token}"),"fixture_only":true,"live_rld":false})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let result = (|| {
        while !STOP.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    require(peer.ip().is_loopback(), "nonloopback wallet peer")?;
                    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                    if let Err(error) =
                        handle(&mut stream, &mut app, &host, &origin, &token, started)
                    {
                        if STOP.load(Ordering::Relaxed) {
                            continue;
                        }
                        let message: String = error.chars().take(2048).collect();
                        let raw =
                            wallet_client::canonical(&json!({"error":message,"fresh":false}))?;
                        let _ = write_response(&mut stream, 409, "application/json", &raw);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    })();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_duplicate_fields_and_nonfinite_or_trailing_json_refuse() {
        for raw in [
            br#"{"action":"status","action":"init"}"#.as_slice(),
            br#"{"request":{"fee":"1","fee":"2"}}"#,
            b"NaN",
            b"{}{}",
        ] {
            assert!(decode_unique(raw).is_err());
        }
        assert!(decode_unique(br#"{"request":{"fee":"1"}}"#).is_ok());
    }

    #[test]
    fn parameterless_actions_refuse_unknown_fields() {
        for action in ["status", "init", "backup"] {
            let valid = json!({"action":action});
            assert!(serde_json::from_value::<crate::wallet_app::Action>(valid).is_ok());
            let unknown = json!({"action":action,"key_file":"/private/key"});
            assert!(serde_json::from_value::<crate::wallet_app::Action>(unknown).is_err());
        }
    }
}
