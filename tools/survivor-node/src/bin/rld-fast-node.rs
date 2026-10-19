//! Serialized native no-value local node. No key/password, remote signing socket,
//! peer directory, cached ledger adoption or monetary activation.
use rld_survivor_node::{
    fast_store::{Limits, Store},
    kernel::{fast, Hash, Result},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, BufRead, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "CLOCK_WAIT".into())
}
fn decode(raw: &str, max: usize) -> Result<Vec<u8>> {
    if raw.len() > max * 2
        || !raw.len().is_multiple_of(2)
        || raw
            .bytes()
            .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
    {
        return Err("INVALID native lowercase hex/bound".into());
    }
    hex::decode(raw).map_err(|_| "INVALID native hex".into())
}
fn hash(raw: &str) -> Result<Hash> {
    decode(raw, 32)?
        .try_into()
        .map_err(|_| "INVALID native hash length".into())
}
fn number(raw: &str) -> Result<u64> {
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("INVALID native timestamp encoding".into());
    }
    raw.parse().map_err(|_| "INVALID native timestamp".into())
}
fn genesis(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path).map_err(|_| "MISSING native genesis")?;
    if !m.is_file() || m.len() != 113 {
        return Err("INVALID native regular genesis file".into());
    }
    let mut raw = Vec::new();
    File::open(path)
        .map_err(|_| "MISSING native genesis")?
        .take(114)
        .read_to_end(&mut raw)
        .map_err(|_| "RESOURCE_WAIT native genesis read")?;
    Ok(raw)
}
#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status {
        head: String,
        tip: String,
    },
    AcceptBlock {
        head: String,
        tip: String,
        block: String,
    },
    FundingOrigin {
        head: String,
        tip: String,
        channel: String,
    },
    Mine {
        head: String,
        tip: String,
        miner: String,
        operations: Vec<String>,
        timestamp: String,
        attempts: u32,
    },
}
struct Job {
    tip: Hash,
    miner: Hash,
    ops: Vec<Vec<u8>>,
    time: u64,
    work: fast::MiningJob,
}
fn outcome(o: rld_survivor_node::fast_store::Outcome) -> Value {
    json!({"admitted_block":hex::encode(o.block),"selected":o.selected,"already_known":o.already_known})
}
fn command(s: &mut Store, r: Request, job: &mut Option<Job>, clock: u64) -> Result<Value> {
    match r {
        Request::Status { head, tip } => {
            s.check(hash(&head)?, hash(&tip)?, clock)?;
            Ok(json!({"state":"CURRENT_LOCAL_SELECTION"}))
        }
        Request::AcceptBlock { head, tip, block } => {
            let raw = decode(&block, 262144)?;
            let o = s.accept(&raw, hash(&head)?, hash(&tip)?, clock)?;
            if job.as_ref().is_some_and(|j| j.tip != s.ledger().tip().id()) {
                *job = None;
            }
            Ok(outcome(o))
        }
        Request::FundingOrigin { head, tip, channel } => {
            let head = hash(&head)?;
            let tip = hash(&tip)?;
            let c = s.current(head, tip, clock)?;
            let origin = c.ledger.funding_origin(hash(&channel)?)?;
            origin.check_current(c.ledger, c.expected_tip, c.now)?;
            Ok(
                json!({"context_hex":hex::encode(origin.context()),"initial_balances":origin.initial().map(|n|n.to_string()),"funding_height":origin.birth_height().to_string(),"current_local_backing":true,"independent_freshness":false}),
            )
        }
        Request::Mine {
            head,
            tip,
            miner,
            operations,
            timestamp,
            attempts,
        } => {
            let head = hash(&head)?;
            let tip = hash(&tip)?;
            s.check(head, tip, clock)?;
            if !(1..=4096).contains(&attempts) || operations.len() > 128 {
                return Err("RESOURCE_WAIT native mining request bound".into());
            }
            let miner = hash(&miner)?;
            let time = number(&timestamp)?;
            let mut ops = operations
                .iter()
                .map(|x| decode(x, 4096))
                .collect::<Result<Vec<_>>>()?;
            ops.sort_by_key(|x| fast::operation_id(x));
            if job
                .as_ref()
                .is_none_or(|j| j.tip != tip || j.miner != miner || j.time != time || j.ops != ops)
            {
                let work = s.ledger().mining_job(miner, ops.clone(), time, clock)?;
                *job = Some(Job {
                    tip,
                    miner,
                    ops,
                    time,
                    work,
                });
            }
            let (block, calls) = job.as_mut().unwrap().work.search(attempts as u64);
            if let Some(raw) = block {
                let o = s.accept(&raw, head, tip, clock)?;
                *job = None;
                let mut v = outcome(o);
                v["state"] = "BLOCK_ADMITTED".into();
                v["block_hex"] = hex::encode(raw).into();
                v["hash_calls"] = calls.to_string().into();
                Ok(v)
            } else {
                Ok(
                    json!({"state":"SEARCH_PENDING","hash_calls":calls.to_string(),"new_block_admitted":false}),
                )
            }
        }
    }
}
fn response(s: &Store, clock: u64, result: Value, diagnostic: Option<&str>) -> Value {
    let l = s.ledger();
    json!({"profile":"RLD-FAST-ESCROW-1","network_kind":"NO_VALUE_ONLY","chain_id":hex::encode(l.chain_id()),"storage_head":hex::encode(s.head()),"selected_tip":hex::encode(l.tip().id()),"selected_revision":s.revision().to_string(),"height":l.tip().height().to_string(),"state_root":hex::encode(l.tip().root()),"work":hex::encode(l.tip().work_bytes()),"known_blocks":s.known_blocks(),"issued":l.issued().to_string(),"locked":l.locked().to_string(),"active_channels":l.active_channels(),"observed_at":clock.to_string(),"storage_state":if s.storage_ready(){"READY"}else{"RESTART_REQUIRED"},"confidence":"CONDITIONAL","independent_freshness":false,"network_monitoring":false,"fast_completion_authorized":false,"mainnet":false,"diagnostic":diagnostic,"result":result})
}
fn emit(v: Value) -> Result<()> {
    println!("{v}");
    io::stdout()
        .flush()
        .map_err(|_| "RESOURCE_WAIT native output".into())
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() < 5 {
        return Err("Usage: rld-fast-node create JOURNAL GENESIS PIN | serve JOURNAL GENESIS PIN LATEST_HEAD | recover JOURNAL GENESIS PIN PRIOR_HEAD BLOCK_ID".into());
    }
    let raw = genesis(Path::new(&a[3]))?;
    let chain = hash(&a[4])?;
    let path = Path::new(&a[2]);
    let clock = now()?;
    let mut s = match a[1].as_str() {
        "create" if a.len() == 5 => Store::create(path, &raw, chain, clock, Limits::default())?,
        "serve" if a.len() == 6 => {
            Store::open(path, &raw, chain, hash(&a[5])?, clock, Limits::default())?
        }
        "recover" if a.len() == 7 => Store::recover(
            path,
            &raw,
            chain,
            hash(&a[5])?,
            hash(&a[6])?,
            clock,
            Limits::default(),
        )?,
        _ => return Err("INVALID native entry arguments".into()),
    };
    emit(response(
        &s,
        clock,
        json!({"state":if a[1]=="create"{"CREATED"}else if a[1]=="recover"{"EXACT_EXISTING_BLOCK_RECOVERED"}else{"READY"}}),
        None,
    ))?;
    if a[1] != "serve" {
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut job = None;
    loop {
        let mut raw = Vec::new();
        let n = Read::by_ref(&mut input)
            .take(2 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(|_| "RESOURCE_WAIT native input")?;
        if n == 0 {
            break;
        }
        let clock = now()?;
        if raw.len() > 2 * 1024 * 1024 || !raw.ends_with(b"\n") {
            emit(response(
                &s,
                clock,
                Value::Null,
                Some("INVALID native request bound"),
            ))?;
            break;
        }
        let r = serde_json::from_slice::<Request>(&raw)
            .map_err(|_| "INVALID native typed request".to_string())
            .and_then(|r| command(&mut s, r, &mut job, clock));
        emit(match r {
            Ok(v) => response(&s, clock, v, None),
            Err(e) => response(&s, clock, Value::Null, Some(&e)),
        })?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
