//! Private native control only. Passwords are zeroized local stdin inputs, never
//! argv/env/log/HTTP values; no plaintext signing key is accepted or returned.
use rld_survivor_node::{
    fast_peer::{codec::Packet, Network},
    fast_session::{
        Action, BackgroundMiner, FeeMonitor, Id, Ingress, MiningRequest, MonitorConfig,
        OpeningRequest, OpeningTerms, Outbound, PoolMiningRequest, Session,
    },
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
    MonitorStart {
        head: Id,
        config: MonitorConfig,
        password: Option<Password>,
    },
    MonitorStop {},
    MiningStart {
        head: Id,
        reward: Id,
    },
    MiningStop {},
    RuntimeStatus {},
    FeePolicyStatus {
        head: Id,
        policy_request: Id,
    },
    OpeningProposal {
        head: Id,
        terms: OpeningTerms,
        timestamp: String,
    },
    PeerOpening {
        head: Id,
        source_request: Id,
        destination: Id,
    },
    PeerOpenPrepare {
        head: Id,
        packet: Id,
        request_id: Id,
        owner: u8,
        timestamp: String,
    },
    PeerOpenCombine {
        head: Id,
        packet: Id,
        request_id: Id,
        prepare_request: Id,
        sign_request: Id,
        review: Id,
    },
    PoolStatus {
        head: Id,
    },
    PoolOperation {
        head: Id,
        operation: Id,
    },
    SubmitAuthorized {
        head: Id,
        request_id: Id,
        sign_request: Id,
    },
    MinePool {
        head: Id,
        miner: Id,
        timestamp: String,
        attempts: u32,
        scan_limit: u16,
        refresh: bool,
    },
    AdmitCandidate {
        head: Id,
        request_id: Id,
        candidate: Id,
    },
    PeerPoolSubmit {
        head: Id,
        packet: Id,
        request_id: Id,
    },
    PeerOperation {
        head: Id,
        operation: Id,
        destination: Id,
    },
    PeerBlock {
        head: Id,
        block: Id,
        destination: Id,
    },
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
    NativeCoin {
        head: Id,
        reference: String,
    },
    NativeWallet {
        head: Id,
        owner: Id,
        after: Option<String>,
        limit: u16,
    },
    WalletCreateKey {
        head: Id,
        name: String,
        password: Password,
    },
    WalletKeyInfo {
        head: Id,
        name: String,
        password: Password,
    },
    OwnerState {
        head: Id,
        actor: Id,
    },
    RetainedDelegation {
        head: Id,
        sign_request: Id,
    },
    TransferDraft {
        head: Id,
        owner: Id,
    },
    NativePreparation {
        head: Id,
        prepare_request: Id,
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
        return Err("Usage: rld-fast-payment-session create ROOT GENESIS PIN | serve ROOT GENESIS PIN LATEST_SESSION_HEAD | recover ROOT GENESIS PIN PRIOR_SESSION_HEAD REQUEST_ID REQUEST_DIGEST | create-control ROOT GENESIS PIN TRUSTED_HEAD_FILE | serve-control ROOT GENESIS PIN TRUSTED_HEAD_FILE [--peer-root PEER_ROOT --peer-head-file PEER_HEAD_FILE [--auto-import-blocks|--auto-sync]] | recover-control ROOT GENESIS PIN TRUSTED_HEAD_FILE | create-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE | serve-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE [--peer-root PEER_ROOT --peer-head-file PEER_HEAD_FILE [--auto-import-blocks|--auto-sync]] | recover-log-control ROOT GENESIS PIN TRUSTED_HEAD_FILE".into());
    }
    let root = Path::new(&a[2]);
    let g = genesis(Path::new(&a[3]))?;
    let chain = id(&a[4])?.0;
    let clock = now()?;
    let serving = a[1] == "serve" || a[1] == "serve-control" || a[1] == "serve-log-control";
    let controlled = a[1] == "serve-control" || a[1] == "serve-log-control";
    let full_sync = controlled && a.len() == 11 && a[10] == "--auto-sync";
    let automatic = controlled && a.len() == 11 && (a[10] == "--auto-import-blocks" || full_sync);
    let mut s = match a[1].as_str() {
        "create" if a.len() == 5 => Session::create(root, &g, chain, clock)?,
        "create-control" if a.len() == 6 => {
            Session::create_controlled(root, &g, chain, Path::new(&a[5]), clock)?
        }
        "create-log-control" if a.len() == 6 => {
            Session::create_log_controlled(root, &g, chain, Path::new(&a[5]), clock)?
        }
        "serve-log-control" if a.len() == 6 || a.len() == 10 || automatic => {
            Session::open_log_controlled(root, &g, chain, Path::new(&a[5]), clock)?
        }
        "recover-log-control" if a.len() == 6 => {
            let (_, out) =
                Session::recover_log_controlled(root, &g, chain, Path::new(&a[5]), clock)?;
            emit(out)?;
            return Ok(());
        }
        "serve-control" if a.len() == 6 || a.len() == 10 || automatic => {
            Session::open_controlled(root, &g, chain, Path::new(&a[5]), clock)?
        }
        "recover-control" if a.len() == 6 => {
            let (_, out) = Session::recover_controlled(root, &g, chain, Path::new(&a[5]), clock)?;
            emit(out)?;
            return Ok(());
        }
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
    let mut peer = if serving && (a.len() == 10 || automatic) {
        if a[6] != "--peer-root" || (a[8] != "--peer-head" && a[8] != "--peer-head-file") {
            return Err("INVALID peer startup flags".into());
        }
        Some(if a[8] == "--peer-head-file" {
            Network::open_controlled(Path::new(&a[7]), chain, Path::new(&a[9]), clock)?
        } else {
            Network::open(Path::new(&a[7]), chain, id(&a[9])?.0, clock)?
        })
    } else {
        None
    };
    if automatic
        && peer
            .as_ref()
            .is_none_or(|n| n.status()["head_control"] != "TRUSTED_FILE")
    {
        return Err("INVALID automatic ingress requires trusted peer control".into());
    }
    let mut ready = s.status(s.head(), clock)?;
    let mut monitor: Option<FeeMonitor> = None;
    let mut miner: Option<BackgroundMiner> = None;
    let mut monitor_clock = None;
    ready["local_runtime"] = runtime_status(&monitor, &miner, full_sync);
    let mut ingress = automatic.then(|| {
        if full_sync {
            Ingress::synchronized()
        } else {
            Ingress::default()
        }
    });
    let mut outbound = full_sync.then(Outbound::default);
    if let Some(o) = &outbound {
        ready["automatic_carriage"] = o.status();
    }
    if let Some(i) = &ingress {
        ready["automatic_native_import"] = i.status();
    }
    if let Some(n) = &peer {
        ready["peer"] = n.status();
    }
    emit(ready)?;
    if !serving {
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
            if let Some(i) = &mut ingress {
                let _ = i.tick(&mut s, n, now()?);
            }
        }
        let clock = now()?;
        let observed = (s.head(), clock);
        if monitor_clock != Some(observed) {
            if let Some(m) = &mut monitor {
                let _ = m.tick(&mut s, clock);
            }
            monitor_clock = Some((s.head(), clock));
        }
        if let Some(m) = &mut miner {
            let _ = m.tick(&mut s, clock);
        }
        if let (Some(o), Some(n)) = (&mut outbound, &mut peer) {
            let _ = o.tick(&mut s, n, now()?);
        }
        let request = match rx.recv_timeout(std::time::Duration::from_millis(
            if miner.is_some() || ingress.as_ref().is_some_and(Ingress::work_pending) {
                1
            } else {
                100
            },
        )) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let clock = now()?;
        let out = request.and_then(|r| match r {
            Request::MonitorStart { head, config, password } => {
                monitor = Some(FeeMonitor::start(&mut s, head.0, config, password.as_ref().map(|p|p.0.as_bytes()), clock)?);
                monitor_clock = None;
                Ok(json!({"monitor_activated":true}))
            },
            Request::MonitorStop {} => {
                s.status(s.head(),clock)?;
                monitor = None;
                Ok(json!({"monitor_activated":false,"retained_liabilities_released":false}))
            },
            Request::MiningStart { head, reward } => {
                miner = Some(BackgroundMiner::start(&mut s, head.0, reward, clock)?);
                Ok(json!({"mining_activated":true}))
            },
            Request::MiningStop {} => {
                s.status(s.head(),clock)?;
                miner = None;
                Ok(json!({"mining_activated":false}))
            },
            Request::RuntimeStatus {} => s.status(s.head(),clock),
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
            Request::OwnerState { head, actor } => s.owner_state(head.0,actor,clock),
            Request::RetainedDelegation { head, sign_request } => s.retained_delegation(head.0, sign_request, clock),
            Request::TransferDraft { head, owner } => s.transfer_draft(head.0, owner, clock),
            Request::NativePreparation { head, prepare_request } => s.native_preparation(head.0, prepare_request, clock),
            Request::NativeWallet { head, owner, after, limit } => s.native_wallet(head.0, owner, after.as_deref(), limit, clock),
            Request::WalletCreateKey { head, name, password } => s.wallet_create_key(head.0, &name, password.0.as_bytes(), clock),
            Request::WalletKeyInfo { head, name, password } => s.wallet_key_info(head.0, &name, password.0.as_bytes(), clock),
            Request::NativeCoin { head, reference } => {
                s.native_coin(head.0, &rld_survivor_node::fast_session::bytes(&reference,34)?, clock)
            }
            Request::FeePolicyStatus{head,policy_request}=>s.fee_policy_status(head.0,policy_request,clock),
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
            Request::OpeningProposal{head,terms,timestamp}=>s.opening_proposal(head.0,terms,timestamp,clock),
            Request::PoolStatus{head}=>s.pool_status(head.0,clock),
            Request::PoolOperation{head,operation}=>Ok(json!({"operation":operation,"operation_hex":hex::encode(s.pool_operation(head.0,operation,clock)?),"pool_custody_only":true})),
            Request::SubmitAuthorized{head,request_id,sign_request}=>s.submit_authorized(head.0,request_id,sign_request,clock),
            Request::MinePool{head,miner,timestamp,attempts,scan_limit,refresh}=>s.mine_pool(head.0,PoolMiningRequest{miner,timestamp,attempts,scan_limit,refresh},clock),
            Request::AdmitCandidate{head,request_id,candidate}=>s.admit_candidate(head.0,request_id,candidate,clock),
            other => peer_command(&mut s, &mut peer, other, clock),
        });
        match out {
            Ok(mut v) => {
                if let Some(o) = &outbound {
                    v["automatic_carriage"] = o.status();
                }
                v["local_runtime"] = runtime_status(&monitor, &miner, full_sync);
                v["session_head"] =
                    serde_json::to_value(Id(s.head())).map_err(|_| "INVALID control head")?;
                if let Some(n) = &peer {
                    v["peer"] = n.status();
                }
                if let Some(i) = &ingress {
                    v["automatic_native_import"] = i.status();
                }
                emit(v)?;
            }
            Err(e) => {
                let mut v = json!({"session_head":Id(s.head()),"diagnostic":e,"fast_completion_authorized":false,"mainnet":false});
                v["local_runtime"] = runtime_status(&monitor, &miner, full_sync);
                if let Some(o) = &outbound {
                    v["automatic_carriage"] = o.status();
                }
                if let Some(n) = &peer {
                    v["peer"] = n.status();
                }
                if let Some(i) = &ingress {
                    v["automatic_native_import"] = i.status();
                }
                emit(v)?;
            }
        }
    }
    Ok(())
}
fn runtime_status(
    monitor: &Option<FeeMonitor>,
    miner: &Option<BackgroundMiner>,
    automatic: bool,
) -> Value {
    json!({"fee_monitor":monitor.as_ref().map(FeeMonitor::status),"ordinary_miner":miner.as_ref().map(BackgroundMiner::status),"unlocks_persisted":false,"automatic_peer_carriage":automatic})
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
        Request::PeerOpening { head, .. }
        | Request::PeerOpenPrepare { head, .. }
        | Request::PeerOpenCombine { head, .. }
        | Request::PeerPoolSubmit { head, .. }
        | Request::PeerOperation { head, .. }
        | Request::PeerBlock { head, .. }
        | Request::PeerStatus { head }
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
        Request::PeerOpening {
            source_request,
            destination,
            ..
        } => {
            let (proposal, partial) = s.opening_data(head, source_request, clock)?;
            let payload = rld_survivor_node::fast_peer::codec::opening_payload(
                s.chain_id(),
                &proposal,
                partial.as_deref(),
            )?;
            queued(
                require_peer(peer)?,
                destination,
                if partial.is_some() { 8 } else { 7 },
                &payload,
                clock,
            )
        }
        Request::PeerOpenPrepare {
            packet,
            request_id,
            owner,
            timestamp,
            ..
        } => {
            let p = incoming(peer, packet, 7)?;
            let (proposal, _) = rld_survivor_node::fast_peer::codec::opening_frame(
                &p.payload,
                s.chain_id(),
                false,
            )?;
            s.execute(
                request_id,
                head,
                Action::OpenPrepare {
                    tip: Id(s.tip()),
                    plan: OpeningRequest {
                        proposal: hex::encode(proposal),
                        owner,
                        timestamp,
                    },
                },
                None,
                clock,
            )
        }
        Request::PeerOpenCombine {
            packet,
            request_id,
            prepare_request,
            sign_request,
            review,
            ..
        } => {
            let p = incoming(peer, packet, 8)?;
            let (proposal, partial) =
                rld_survivor_node::fast_peer::codec::opening_frame(&p.payload, s.chain_id(), true)?;
            let (original, _) = s.opening_data(head, prepare_request, clock)?;
            if proposal != original {
                return Err("INVALID changed counterparty opening proposal".into());
            }
            s.execute(
                request_id,
                head,
                Action::OpenCombine {
                    tip: Id(s.tip()),
                    prepare_request,
                    sign_request,
                    review,
                    counterparty_partial: hex::encode(partial.unwrap()),
                },
                None,
                clock,
            )
        }
        Request::PeerPoolSubmit {
            packet, request_id, ..
        } => {
            let p = incoming(peer, packet, 6)?;
            let raw = rld_survivor_node::fast_peer::codec::operation(&p.payload, s.chain_id())?;
            s.execute(
                request_id,
                head,
                Action::PoolSubmit {
                    tip: Id(s.tip()),
                    operation: hex::encode(raw),
                },
                None,
                clock,
            )
        }
        Request::PeerOperation {
            operation,
            destination,
            ..
        } => {
            let raw = s.pool_operation(head, operation, clock)?;
            let data = rld_survivor_node::fast_peer::codec::operation_payload(s.chain_id(), &raw)?;
            queued(require_peer(peer)?, destination, 6, &data, clock)
        }
        Request::PeerBlock {
            block, destination, ..
        } => {
            let raw = s.retained_block(head, block, clock)?;
            queued(require_peer(peer)?, destination, 1, &raw, clock)
        }
        Request::PeerStatus { .. } => {
            let n = require_peer(peer)?;
            Ok(
                json!({"peer_head":Id(n.head()),"neighbors":n.admitted_ids().into_iter().map(Id).collect::<Vec<_>>(),"transport_custody_only":true}),
            )
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
