//! Private native control only. Passwords are zeroized local stdin inputs, never
//! argv/env/log/HTTP values; no plaintext signing key is accepted or returned.
use rld_survivor_node::{
    fast_peer::{codec::Packet, Network},
    fast_session::{Action, Id, MiningRequest, Session},
    kernel::Result,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    path::Path,
    sync::mpsc,
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
    ExitEvidence {
        head: Id,
        actor: Id,
    },
    MiningCandidate {
        head: Id,
        miner: Id,
        operations: Vec<String>,
        timestamp: String,
        attempts: u32,
    },
    PeerStatus {
        head: Id,
    },
    PeerInventory {
        head: Id,
    },
    PeerData {
        head: Id,
        packet: Id,
    },
    PeerQueue {
        head: Id,
        destination: Id,
        kind: u8,
        payload: String,
    },
    PeerInvoice {
        head: Id,
        actor: Id,
        invoice: Id,
        destination: Id,
    },
    PeerPartial {
        head: Id,
        actor: Id,
        invoice: Id,
        destination: Id,
    },
    PeerCombineSend {
        head: Id,
        actor: Id,
        invoice: Id,
        partial: Id,
        destinations: Vec<Id>,
    },
    PeerAck {
        head: Id,
        actor: Id,
        receipt: Id,
        destination: Id,
    },
    PeerPrepare {
        head: Id,
        actor: Id,
        packet: Id,
        request_id: Id,
    },
    PeerComplete {
        head: Id,
        actor: Id,
        invoice: Id,
        partial: Id,
        ack: Id,
        request_id: Id,
    },
    PeerImport {
        head: Id,
        packet: Id,
        request_id: Id,
    },
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
        "serve" if a.len() == 6 || a.len() == 10 => {
            Session::open(root, &g, chain, id(&a[5])?.0, clock)?
        }
        "recover" if a.len() == 8 => {
            let (_, out) =
                Session::recover(root, &g, chain, id(&a[5])?.0, id(&a[6])?, id(&a[7])?, clock)?;
            emit(out)?;
            return Ok(());
        }
        _ => return Err("INVALID payment session entry".into()),
    };
    let mut peer = if a[1] == "serve" && a.len() == 10 {
        if a[6] != "--peer-root" || a[8] != "--peer-head" {
            return Err("INVALID peer startup flags".into());
        }
        Some(Network::open(Path::new(&a[7]), chain, id(&a[9])?.0, clock)?)
    } else {
        None
    };
    let mut ready = s.status(s.head(), clock)?;
    if let Some(n) = &peer {
        ready["peer"] = n.status();
    }
    emit(ready)?;
    if a[1] != "serve" {
        return Ok(());
    }
    let (tx, rx) = mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        loop {
            let mut b = Zeroizing::new(Vec::new());
            let n = Read::by_ref(&mut input)
                .take(2 * 1024 * 1024 + 1)
                .read_until(b'\n', &mut b);
            match n {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if b.len() > 2 * 1024 * 1024 || !b.ends_with(b"\n") {
                        let _ = tx.send(Err("INVALID bounded request".into()));
                        break;
                    }
                    let request = serde_json::from_slice::<Request>(&b)
                        .map_err(|_| "INVALID typed native control request".to_string());
                    if tx.send(request).is_err() {
                        break;
                    }
                }
            }
        }
    });
    loop {
        if let Some(n) = peer.as_mut() {
            let _ = n.tick(now()?);
        }
        let request = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let clock = now()?;
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
            Request::MiningCandidate {
                head,
                miner,
                operations,
                timestamp,
                attempts,
            } => s.mining_candidate(
                head.0,
                MiningRequest {
                    miner,
                    operations,
                    timestamp,
                    attempts,
                },
                clock,
            ),
            Request::ExitEvidence { head, actor } => s.exit_evidence(head.0, actor, clock),
            other => peer_command(&mut s, &mut peer, other, clock),
        });
        match out {
            Ok(mut v) => {
                v["session_head"] =
                    serde_json::to_value(Id(s.head())).map_err(|_| "INVALID control head")?;
                if let Some(n) = &peer {
                    v["peer"] = n.status();
                }
                emit(v)?;
            }
            Err(e) => {
                let mut v = json!({"session_head":Id(s.head()),"diagnostic":e,"fast_completion_authorized":false,"mainnet":false});
                if let Some(n) = &peer {
                    v["peer"] = n.status();
                }
                emit(v)?;
            }
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

fn require_peer(peer: &mut Option<Network>) -> Result<&mut Network> {
    peer.as_mut()
        .ok_or("MISSING configured payment peer adapter".into())
}
fn incoming(peer: &mut Option<Network>, id: Id, kind: u8) -> Result<Packet> {
    let p = require_peer(peer)?.received(id.0)?;
    if p.kind != kind {
        return Err("INVALID incoming peer payload kind".into());
    }
    Ok(p)
}
fn queued(n: &mut Network, destination: Id, kind: u8, data: &[u8], clock: u64) -> Result<Value> {
    let packet = n.queue(destination.0, kind, data, clock)?;
    Ok(
        json!({"packet":Id(packet),"peer_head":Id(n.head()),"transport_custody_only":true,"fast_completion_authorized":false}),
    )
}
fn peer_command(
    s: &mut Session,
    peer: &mut Option<Network>,
    r: Request,
    clock: u64,
) -> Result<Value> {
    use rld_survivor_node::fast_session::bytes;
    let head = match &r {
        Request::PeerStatus { head }
        | Request::PeerInventory { head }
        | Request::PeerData { head, .. }
        | Request::PeerQueue { head, .. }
        | Request::PeerInvoice { head, .. }
        | Request::PeerPartial { head, .. }
        | Request::PeerCombineSend { head, .. }
        | Request::PeerAck { head, .. }
        | Request::PeerPrepare { head, .. }
        | Request::PeerComplete { head, .. }
        | Request::PeerImport { head, .. } => head.0,
        _ => return Err("INVALID peer command".into()),
    };
    s.status(head, clock)?;
    match r {
        Request::PeerStatus { .. } => {
            let n = require_peer(peer)?;
            Ok(json!({"peer_head":Id(n.head()),"transport_custody_only":true}))
        }
        Request::PeerInventory { .. } => {
            Ok(json!({"packets":require_peer(peer)?.inventory()?,"transport_custody_only":true}))
        }
        Request::PeerData { packet, .. } => {
            let p = require_peer(peer)?.received(packet.0)?;
            Ok(
                json!({"packet":Id(p.id),"source":Id(p.sender),"kind":p.kind,"payload":hex::encode(p.payload),"transport_custody_only":true,"ledger_acceptance_known":false}),
            )
        }
        Request::PeerQueue {
            destination,
            kind,
            payload,
            ..
        } => queued(
            require_peer(peer)?,
            destination,
            kind,
            &bytes(&payload, 262144)?,
            clock,
        ),
        Request::PeerInvoice {
            actor,
            invoice,
            destination,
            ..
        } => {
            let p = s.pending(head, actor, invoice, clock)?;
            let raw = bytes(
                p["invoice_hex"]
                    .as_str()
                    .ok_or("MISSING retained invoice")?,
                575,
            )?;
            queued(require_peer(peer)?, destination, 2, &raw, clock)
        }
        Request::PeerPartial {
            actor,
            invoice,
            destination,
            ..
        } => {
            let p = s.pending(head, actor, invoice, clock)?;
            let raw = bytes(
                p["partial_hex"]
                    .as_str()
                    .ok_or("MISSING retained partial")?,
                129,
            )?;
            let payload = [invoice.0.as_slice(), &raw].concat();
            queued(require_peer(peer)?, destination, 3, &payload, clock)
        }
        Request::PeerCombineSend {
            actor,
            invoice,
            partial,
            destinations,
            ..
        } => {
            let p = incoming(peer, partial, 3)?;
            if p.payload[..32] != invoice.0 {
                return Err("INVALID partial invoice ID".into());
            }
            if destinations.is_empty()
                || destinations.len() > 16
                || destinations
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != destinations.len()
            {
                return Err("INVALID peer destinations".into());
            }
            let raw = s.combine(head, actor, invoice, &p.payload[32..], clock)?;
            let mut sent = Vec::new();
            for destination in destinations {
                sent.push(queued(require_peer(peer)?, destination, 4, &raw, clock)?);
            }
            Ok(
                json!({"sent":sent,"full_receipt_constructed":true,"fast_completion_authorized":false}),
            )
        }
        Request::PeerAck {
            actor,
            receipt,
            destination,
            ..
        } => {
            let p = s.pending(head, actor, receipt, clock)?;
            let raw = bytes(
                p["ack_hex"]
                    .as_str()
                    .ok_or("MISSING retained acknowledgment")?,
                340,
            )?;
            queued(require_peer(peer)?, destination, 5, &raw, clock)
        }
        Request::PeerPrepare {
            actor,
            packet,
            request_id,
            ..
        } => {
            let p = require_peer(peer)?.received(packet.0)?;
            let tip = Id(s.tip());
            let action = match p.kind {
                2 => Action::OwnerPrepare {
                    tip,
                    actor,
                    invoice: hex::encode(p.payload),
                },
                4 => Action::RetainerPrepare {
                    tip,
                    actor,
                    receipt: hex::encode(p.payload),
                },
                _ => return Err("INVALID incoming prepare kind".into()),
            };
            s.execute(request_id, head, action, None, clock)
        }
        Request::PeerComplete {
            actor,
            invoice,
            partial,
            ack,
            request_id,
            ..
        } => {
            let p = incoming(peer, partial, 3)?;
            let a = incoming(peer, ack, 5)?;
            if p.payload[..32] != invoice.0 {
                return Err("INVALID incoming partial invoice ID".into());
            }
            let raw = s.combine(head, actor, invoice, &p.payload[32..], clock)?;
            s.execute(
                request_id,
                head,
                Action::OwnerComplete {
                    tip: Id(s.tip()),
                    actor,
                    receipt: hex::encode(raw),
                    ack: hex::encode(a.payload),
                },
                None,
                clock,
            )
        }
        Request::PeerImport {
            packet, request_id, ..
        } => {
            let p = incoming(peer, packet, 1)?;
            let mut v = s.execute(
                request_id,
                head,
                Action::Native {
                    tip: Id(s.tip()),
                    block: hex::encode(p.payload),
                },
                None,
                clock,
            )?;
            v["imported_packet"] = serde_json::to_value(packet).map_err(|_| "INVALID packet ID")?;
            v["native_import_checked"] = true.into();
            Ok(v)
        }
        _ => Err("INVALID peer command".into()),
    }
}
