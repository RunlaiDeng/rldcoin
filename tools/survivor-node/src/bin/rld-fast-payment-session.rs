//! Private native control only. Passwords are zeroized local stdin inputs, never
//! argv/env/log/HTTP values; no plaintext signing key is accepted or returned.
use rld_survivor_node::{
    fast_session::{Action, Id, Session},
    kernel::Result,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
struct Password(Zeroizing<String>);
impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let p = Zeroizing::new(String::deserialize(d)?);
        if !(1..=1024).contains(&p.len()) {
            return Err(serde::de::Error::custom("INVALID password bound"));
        }
        Ok(Self(p))
    }
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Execute {
        head: Id,
        request_id: Id,
        action: Action,
        password: Option<Password>,
    },
    Status {
        head: Id,
    },
    Pending {
        head: Id,
        actor: Id,
        invoice: Id,
    },
    Propose {
        head: Id,
        actor: Id,
        payer: u8,
        amount: String,
        invoice: Id,
    },
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "CLOCK_WAIT".into())
}
fn id(s: &str) -> Result<Id> {
    serde_json::from_value(Value::String(s.into())).map_err(|_| "INVALID ID".into())
}
fn genesis(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|_| "MISSING genesis")?;
    if !m.is_file() || m.len() != 113 {
        return Err("INVALID native genesis input".into());
    }
    let mut b = vec![];
    File::open(path)
        .map_err(|_| "MISSING genesis")?
        .take(114)
        .read_to_end(&mut b)
        .map_err(|_| "RESOURCE_WAIT genesis read")?;
    Ok(b)
}
fn emit(v: Value) -> Result<()> {
    println!("{v}");
    io::stdout()
        .flush()
        .map_err(|_| "RESOURCE_WAIT control output".into())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() < 5 {
        return Err("Usage: rld-fast-payment-session create ROOT GENESIS PIN | serve ROOT GENESIS PIN LATEST_SESSION_HEAD | recover ROOT GENESIS PIN PRIOR_SESSION_HEAD REQUEST_ID REQUEST_DIGEST".into());
    }
    let root = Path::new(&a[2]);
    let g = genesis(Path::new(&a[3]))?;
    let chain = id(&a[4])?.0;
    let clock = now()?;
    let mut s = match a[1].as_str() {
        "create" if a.len() == 5 => Session::create(root, &g, chain, clock)?,
        "serve" if a.len() == 6 => Session::open(root, &g, chain, id(&a[5])?.0, clock)?,
        "recover" if a.len() == 8 => {
            let (_, out) =
                Session::recover(root, &g, chain, id(&a[5])?.0, id(&a[6])?, id(&a[7])?, clock)?;
            emit(out)?;
            return Ok(());
        }
        _ => return Err("INVALID payment session entry".into()),
    };
    emit(s.status(s.head(), clock)?)?;
    if a[1] != "serve" {
        return Ok(());
    }
    let mut input = io::stdin().lock();
    loop {
        let mut b = Zeroizing::new(Vec::new());
        let n = Read::by_ref(&mut input)
            .take(2 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut b)
            .map_err(|_| "RESOURCE_WAIT native control input")?;
        if n == 0 {
            break;
        }
        if b.len() > 2 * 1024 * 1024 || !b.ends_with(b"\n") {
            emit(
                json!({"session_head":Id(s.head()),"diagnostic":"INVALID bounded request","fast_completion_authorized":false}),
            )?;
            break;
        }
        let clock = now()?;
        let request = serde_json::from_slice::<Request>(&b)
            .map_err(|_| "INVALID typed native control request".to_string());
        let out = request.and_then(|r| match r {
            Request::Execute {
                head,
                request_id,
                action,
                password,
            } => s.execute(
                request_id,
                head.0,
                action,
                password.as_ref().map(|p| p.0.as_bytes()),
                clock,
            ),
            Request::Status { head } => s.status(head.0, clock),
            Request::Pending {
                head,
                actor,
                invoice,
            } => s.pending(head.0, actor, invoice, clock),
            Request::Propose {
                head,
                actor,
                payer,
                amount,
                invoice,
            } => {
                if amount.is_empty()
                    || (amount.len() > 1 && amount.starts_with('0'))
                    || !amount.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err("INVALID amount encoding".into());
                }
                s.propose(
                    head.0,
                    actor,
                    payer,
                    amount.parse().map_err(|_| "INVALID amount")?,
                    invoice.0,
                    clock,
                )
            }
        });
        match out {
            Ok(v) => emit(v)?,
            Err(e) => emit(
                json!({"session_head":Id(s.head()),"diagnostic":e,"fast_completion_authorized":false,"mainnet":false}),
            )?,
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
