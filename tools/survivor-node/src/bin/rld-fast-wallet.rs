//! Interactive private native wallet. Secrets use a local echo-free terminal;
//! the existing serialized node owns all ledger, review and signing authority.
use rld_survivor_node::{
    fast_session::{Action, Id, TransferOutput, TransferRequest},
    kernel::Result,
};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
#[path = "fast_wallet/menu.rs"]
mod fast_menu;
const UNIT: u128 = 1_000_000_000_000_000_000_000_000;
const FRAME: usize = 1024 * 1024;
fn fail(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(fail)
}
fn rid() -> Result<Id> {
    let mut b = [0; 32];
    getrandom::getrandom(&mut b).map_err(fail)?;
    Ok(Id(b))
}
fn parse_id(s: &str) -> Result<Id> {
    serde_json::from_value(json!(s))
        .map_err(|_| "Use a complete lowercase public identifier".into())
}
fn field_id(v: &Value, k: &str) -> Result<Id> {
    serde_json::from_value(v[k].clone()).map_err(|_| format!("Missing native {k}"))
}
fn number(v: &Value) -> Result<u128> {
    v.as_str()
        .ok_or("Missing native integer")?
        .parse()
        .map_err(fail)
}
fn amount(s: &str) -> Result<u128> {
    let mut parts = s.split('.');
    let whole = parts.next().unwrap_or("");
    let fraction = parts.next().unwrap_or("");
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 24
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || parts.next().is_some()
    {
        return Err("Use an unsigned RLD amount with at most24 decimal places".into());
    }
    let whole = whole.parse::<u128>().map_err(fail)?;
    let tail = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>().map_err(fail)?
    };
    whole
        .checked_mul(UNIT)
        .and_then(|v| v.checked_add(tail.checked_mul(10u128.pow(24 - fraction.len() as u32))?))
        .ok_or("Amount exceeds native integer capacity".into())
}
fn display_amount(n: u128) -> String {
    if n.is_multiple_of(UNIT) {
        return (n / UNIT).to_string();
    }
    format!("{}.{:024}", n / UNIT, n % UNIT)
        .trim_end_matches('0')
        .to_string()
}
fn text(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush().map_err(fail)?;
    let mut raw = Vec::new();
    let n = io::stdin()
        .lock()
        .take(4098)
        .read_until(b'\n', &mut raw)
        .map_err(fail)?;
    if n == 0 {
        return Err("Input closed".into());
    }
    if n > 4096 || raw.last() != Some(&b'\n') {
        return Err("Input line too long; restart the wallet".into());
    }
    let s = String::from_utf8(raw).map_err(|_| "Use UTF-8 input")?;
    Ok(s.trim().to_string())
}
fn default(label: &str, value: &str) -> Result<String> {
    let s = text(&format!("{label} [{value}]"))?;
    Ok(if s.is_empty() { value.to_string() } else { s })
}
fn approve() -> Result<bool> {
    Ok(text("Type YES to approve this exact review")? == "YES")
}
fn stty() -> Result<PathBuf> {
    for p in ["/bin/stty", "/usr/bin/stty"] {
        if Path::new(p).is_file() {
            return Ok(p.into());
        }
    }
    Err("Native terminal control is unavailable".into())
}
struct Echo {
    tool: PathBuf,
    state: String,
    tty: File,
}
impl Drop for Echo {
    fn drop(&mut self) {
        if let Ok(input) = self.tty.try_clone() {
            let _ = Command::new(&self.tool)
                .arg(&self.state)
                .stdin(Stdio::from(input))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
fn secret(label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "A local native terminal is required for passwords")?;
    let tool = stty()?;
    let saved = Command::new(&tool)
        .arg("-g")
        .stdin(Stdio::from(tty.try_clone().map_err(fail)?))
        .output()
        .map_err(fail)?;
    if !saved.status.success() || saved.stdout.len() > 4096 {
        return Err("Cannot read native terminal settings".into());
    }
    let state = String::from_utf8(saved.stdout)
        .map_err(fail)?
        .trim()
        .to_string();
    if state.is_empty() {
        return Err("Missing native terminal settings".into());
    }
    let _echo = Echo {
        tool: tool.clone(),
        state,
        tty: tty.try_clone().map_err(fail)?,
    };
    if !Command::new(&tool)
        .arg("-echo")
        .stdin(Stdio::from(tty.try_clone().map_err(fail)?))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(fail)?
        .success()
    {
        return Err("Cannot disable native terminal echo".into());
    }
    write!(tty, "{label}: ").map_err(fail)?;
    tty.flush().map_err(fail)?;
    let mut raw = Zeroizing::new(Vec::new());
    let mut too_long = false;
    loop {
        let mut b = [0u8];
        tty.read_exact(&mut b).map_err(fail)?;
        if b[0] == b'\n' {
            break;
        }
        if raw.len() < 1024 {
            raw.push(b[0]);
        } else {
            too_long = true;
        }
    }
    writeln!(tty).map_err(fail)?;
    if too_long || raw.is_empty() || std::str::from_utf8(&raw).is_err() {
        return Err("Password must contain1..1024 UTF-8 bytes".into());
    }
    Ok(raw)
}
fn response(reader: &mut impl BufRead) -> Result<Value> {
    let mut raw = Vec::new();
    reader
        .take((FRAME + 1) as u64)
        .read_until(b'\n', &mut raw)
        .map_err(fail)?;
    if raw.is_empty() || raw.len() > FRAME || raw.last() != Some(&b'\n') {
        return Err("Native response unavailable or exceeds the wallet bound".into());
    }
    serde_json::from_slice(&raw).map_err(|_| "Invalid native response".into())
}
struct Node {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Result<Value>>,
    head: Id,
    tip: Id,
    height: u128,
    stamp: u64,
    peer: bool,
    healthy: bool,
}
impl Node {
    fn start(program: &Path, args: &[String]) -> Result<(Self, Value)> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(fail)?;
        let input = child.stdin.take();
        let stdout = child.stdout.take().ok_or("Missing native stdout")?;
        let (tx, rx) = mpsc::sync_channel(4);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let v = response(&mut reader);
                let stop = v.is_err();
                if tx.send(v).is_err() || stop {
                    break;
                }
            }
        });
        let mut node = Self {
            child,
            input,
            output: rx,
            head: Id([0; 32]),
            tip: Id([0; 32]),
            height: 0,
            stamp: 0,
            peer: false,
            healthy: true,
        };
        let ready = node.read()?;
        node.observe(&ready)?;
        println!(
            "Network mode: {}",
            ready["network_kind"].as_str().unwrap_or("UNKNOWN")
        );
        node.peer = ready["peer"].is_object();
        Ok((node, ready))
    }
    fn read(&mut self) -> Result<Value> {
        let result = self
            .output
            .recv_timeout(Duration::from_secs(120))
            .map_err(|_| {
                "Native response interrupted; stop and use controlled recovery before resubmission"
            })
            .unwrap_or_else(|e| Err(e.into()));
        if result.is_err() {
            self.healthy = false;
        }
        result
    }
    fn observe(&mut self, v: &Value) -> Result<()> {
        if v["session_head"].is_string() {
            self.head = field_id(v, "session_head")?;
        }
        if v["selected_tip"].is_string() {
            self.tip = field_id(v, "selected_tip")?;
        }
        if v["height"].is_string() {
            self.height = number(&v["height"])?;
        }
        if v["selected_timestamp"].is_string() {
            self.stamp = u64::try_from(number(&v["selected_timestamp"])?).map_err(fail)?;
        }
        if let Some(d) = v["diagnostic"].as_str() {
            return Err(format!("Native request refused: {d:?}"));
        }
        Ok(())
    }
    fn call(&mut self, mut v: Value, password: Option<&[u8]>) -> Result<Value> {
        if !self.healthy {
            return Err("Native stream interrupted; close and use controlled recovery".into());
        }
        if v["command"] != "runtime_status" {
            v["head"] = json!(self.head);
        }
        let mut raw = Zeroizing::new(serde_json::to_vec(&v).map_err(fail)?);
        if let Some(password) = password {
            let p = std::str::from_utf8(password).map_err(|_| "Password must use UTF-8")?;
            if raw.pop() != Some(b'}') {
                return Err("Invalid private request object".into());
            }
            raw.extend(b",\"password\":");
            serde_json::to_writer(&mut *raw, p).map_err(fail)?;
            raw.push(b'}');
        }
        if raw.len() > FRAME {
            return Err("Private request exceeds wallet bound".into());
        }
        let input = self.input.as_mut().ok_or("Native session stopped")?;
        let sent = input
            .write_all(&raw)
            .and_then(|_| input.write_all(b"\n"))
            .and_then(|_| input.flush())
            .map_err(fail);
        if let Err(e) = sent {
            self.healthy = false;
            return Err(e);
        }
        let reply = self.read()?;
        if let Err(e) = self.observe(&reply) {
            if !reply["diagnostic"].is_string() {
                self.healthy = false;
            }
            return Err(e);
        }
        Ok(reply)
    }
    fn refresh(&mut self) -> Result<Value> {
        self.call(json!({"command":"runtime_status"}), None)
    }
    fn execute(&mut self, action: Action, password: Option<&[u8]>) -> Result<(Id, Value)> {
        let request = rid()?;
        let v = self.call(
            json!({"command":"execute","request_id":request,"action":action}),
            password,
        )?;
        Ok((request, v))
    }
    fn queue(&mut self, request: Id) -> Result<()> {
        self.refresh()?;
        let v = self.call(
            json!({"command":"submit_authorized","request_id":rid()?,"sign_request":request}),
            None,
        )?;
        println!(
            "Payment queued for native mining: {}",
            v["pool_operation"].as_str().unwrap_or("retained")
        );
        println!("Inclusion and confirmation remain pending.");
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        self.input.take();
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().map_err(fail)? {
                return if status.success() {
                    Ok(())
                } else {
                    Err("Native process exited with an error; retain state and recover".into())
                };
            }
            if Instant::now() >= end {
                self.child.kill().map_err(fail)?;
                self.child.wait().map_err(fail)?;
                return Err("Native shutdown interrupted; controlled recovery is required".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.input.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
#[derive(Clone)]
struct Account {
    name: String,
    owner: Id,
    path: String,
}
struct Wallet {
    node: Node,
    account: Option<Account>,
}
impl Wallet {
    fn selected(&self) -> Result<Account> {
        self.account
            .clone()
            .ok_or("Create or select a wallet first".into())
    }
    fn select(&mut self, create: bool) -> Result<()> {
        let name = text("Wallet name")?;
        let password = secret(if create {
            "New password"
        } else {
            "Wallet password"
        })?;
        if create && *password != *secret("Repeat new password")? {
            return Err("Passwords differ".into());
        }
        self.node.refresh()?;
        let v = self.node.call(
            json!({"command":if create{"wallet_create_key"}else{"wallet_key_info"},"name":name}),
            Some(&password),
        )?;
        let owner = field_id(&v, "owner")?;
        let path = v["key_file"]
            .as_str()
            .ok_or("Missing native key path")?
            .to_string();
        self.account = Some(Account { name, owner, path });
        println!("Public receiving address: {}", hex::encode(owner.0));
        Ok(())
    }
    fn balances(&mut self) -> Result<()> {
        let a = self.selected()?;
        self.node.refresh()?;
        let v = self.node.call(
            json!({"command":"native_wallet","owner":a.owner,"after":null,"limit":16}),
            None,
        )?;
        for (label, field) in [
            ("Ordinary native total", "native_total"),
            (
                "Mature and locally unreserved",
                "mature_locally_unreserved_total",
            ),
            ("Immature", "immature_total"),
            ("Locally reserved", "locally_reserved_total"),
        ] {
            println!("{label}: {} RLD", display_amount(number(&v[field])?));
        }
        println!("Fast-channel balances are separate. Other wallets' reservations are unknown.");
        Ok(())
    }
    fn inputs(&mut self, owner: Id, needed: u128) -> Result<(Vec<String>, u128)> {
        let mut cursor = Value::Null;
        let mut found = Vec::new();
        let mut total = 0u128;
        let mut pinned = None;
        loop {
            let v = self.node.call(
                json!({"command":"native_wallet","owner":owner,"after":cursor,"limit":16}),
                None,
            )?;
            if let Some(head) = pinned {
                if self.node.head != head {
                    return Err("Native state changed; restart input selection".into());
                }
            } else {
                pinned = Some(self.node.head);
            }
            for coin in v["outputs"]
                .as_array()
                .ok_or("Missing native output page")?
            {
                if coin["manual_input_candidate"] == true {
                    if found.len() == 32 {
                        return Err(
                            "Payment needs more than32 inputs; consolidate funds first".into()
                        );
                    }
                    found.push(
                        coin["reference"]
                            .as_str()
                            .ok_or("Missing native reference")?
                            .to_string(),
                    );
                    total = total
                        .checked_add(number(&coin["amount"])?)
                        .ok_or("Input sum overflow")?;
                    if total >= needed {
                        return Ok((found, total));
                    }
                }
            }
            cursor = v["next_cursor"].clone();
            if cursor.is_null() {
                return Err("Not enough mature locally unreserved native funds".into());
            }
        }
    }
    fn review_sign(&mut self, action: Action, a: &Account) -> Result<Option<(Id, Value)>> {
        let (prepared, v) = self.node.execute(action, None)?;
        let review = &v["review"];
        let required = match review["operation"].as_str() {
            Some("TRANSFER" | "CLOSE" | "PRINCIPAL_CHALLENGE" | "MINER_FEE_CLAIM" | "SETTLE") => {
                field_id(review, "spending_owner")?
            }
            Some("MINER_DELEGATION") => field_id(review, "miner")?,
            Some("OPEN") => {
                let own = review["own_index"]
                    .as_u64()
                    .filter(|i| *i < 2)
                    .ok_or("Missing opening owner index")? as usize;
                serde_json::from_value(review["owners"][own].clone()).map_err(fail)?
            }
            _ => return Err("Unsupported native wallet review type".into()),
        };
        if required != a.owner {
            return Err(
                "Selected wallet is not the required signer; review remains unsigned".into(),
            );
        }
        println!(
            "\nReview: {}",
            review["operation"].as_str().unwrap_or("UNKNOWN")
        );
        println!("Selected native tip: {}", review["chain_selected_tip"]);
        println!("Retained preparation: {}", hex::encode(prepared.0));
        println!(
            "Review identifier: {}",
            hex::encode(field_id(&v, "review_digest")?.0)
        );
        if review["operation"] == "TRANSFER" {
            for output in review["outputs"]
                .as_array()
                .ok_or("Missing transfer outputs")?
            {
                println!(
                    "  {} RLD -> {}",
                    display_amount(number(&output["amount"])?),
                    output["owner"]
                );
            }
            println!(
                "Network fee: {} RLD",
                display_amount(number(&review["operation_fee"])?)
            );
            println!("Expiry height: {}", review["expiry_height"]);
        } else if review["operation"] == "MINER_DELEGATION" {
            println!(
                "Funding channel: {}\nReceipt service: {}",
                review["channel"], review["retainer"]
            );
            println!("Delegation grants no principal or fee-input spending rights.");
        } else {
            println!("{}", serde_json::to_string_pretty(review).map_err(fail)?);
        }
        if !approve()? {
            println!("Review retained without a signature.");
            return Ok(None);
        }
        let password = secret("Wallet password")?;
        let (_, signed) = self.node.execute(
            Action::OnchainSign {
                tip: self.node.tip,
                prepare_request: prepared,
                review: field_id(&v, "review_digest")?,
                key_file: a.path.clone(),
                approved: true,
            },
            Some(&password),
        )?;
        let request = field_id(&signed, "request_id")?;
        println!("Retained signing request: {}", hex::encode(request.0));
        Ok(Some((request, signed)))
    }
    fn transfer(&mut self) -> Result<()> {
        let a = self.selected()?;
        let recipient = parse_id(&text("Recipient address")?)?;
        let value = amount(&text("Amount in RLD")?)?;
        let fee = amount(&default(
            "Network fee in RLD",
            "0.000000000000000000000001",
        )?)?;
        if value == 0 || fee == 0 {
            return Err("Payment and network fee must be positive".into());
        }
        let needed = value.checked_add(fee).ok_or("Amount and fee overflow")?;
        self.node.refresh()?;
        let (inputs, total) = self.inputs(a.owner, needed)?;
        let mut outputs = vec![TransferOutput {
            owner: recipient,
            amount: value.to_string(),
        }];
        if total > needed {
            outputs.push(TransferOutput {
                owner: a.owner,
                amount: (total - needed).to_string(),
            });
        }
        let plan = TransferRequest {
            owner: a.owner,
            inputs,
            outputs,
            fee: fee.to_string(),
            expiry: self
                .node
                .height
                .checked_add(144)
                .ok_or("Expiry height overflow")?
                .to_string(),
            timestamp: now()?
                .max(
                    self.node
                        .stamp
                        .checked_add(1)
                        .ok_or("Native timestamp overflow")?,
                )
                .to_string(),
        };
        if let Some((signed, _)) = self.review_sign(
            Action::TransferPrepare {
                tip: self.node.tip,
                plan,
            },
            &a,
        )? {
            self.node.queue(signed)?;
        }
        Ok(())
    }
    fn resume(&mut self) -> Result<()> {
        let a = self.selected()?;
        self.node.refresh()?;
        let v = self
            .node
            .call(json!({"command":"transfer_draft","owner":a.owner}), None)?;
        let draft = &v["draft"];
        if draft.is_null() {
            println!("No retained transfer draft.");
            return Ok(());
        }
        println!(
            "Original native preparation time: {}",
            draft["first_prepared_at"]
        );
        let mut plan: TransferRequest =
            serde_json::from_value(draft["plan"].clone()).map_err(fail)?;
        if plan.owner != a.owner {
            return Err("Retained draft belongs to another owner".into());
        }
        for output in &plan.outputs {
            println!(
                "  {} RLD -> {}",
                display_amount(output.amount.parse::<u128>().map_err(fail)?),
                hex::encode(output.owner.0)
            );
        }
        println!(
            "Retained fee: {} RLD; expiry height: {}",
            display_amount(plan.fee.parse::<u128>().map_err(fail)?),
            plan.expiry
        );
        if draft["retained_sign_request"].is_string() {
            println!("An exact signature is already retained. No new signature is needed.");
            println!("Current native inclusion has not been evaluated by this draft view.");
            if approve()? {
                self.node.queue(field_id(draft, "retained_sign_request")?)?;
            }
        } else {
            self.node.call(
                json!({"command":"native_wallet","owner":a.owner,"after":null,"limit":1}),
                None,
            )?;
            plan.timestamp = now()?
                .max(
                    self.node
                        .stamp
                        .checked_add(1)
                        .ok_or("Native timestamp overflow")?,
                )
                .to_string();
            if let Some((signed, _)) = self.review_sign(
                Action::TransferPrepare {
                    tip: self.node.tip,
                    plan,
                },
                &a,
            )? {
                self.node.queue(signed)?;
            }
        }
        Ok(())
    }
    fn delegation(&mut self) -> Result<()> {
        let a = self.selected()?;
        let channel = parse_id(&text("Funding channel")?)?;
        let retainer = parse_id(&text("Separate receipt-service public address")?)?;
        self.node.refresh()?;
        if let Some((request, v)) = self.review_sign(
            Action::DelegationPrepare {
                tip: self.node.tip,
                channel,
                retainer,
            },
            &a,
        )? {
            println!("Retained authorization request: {}", hex::encode(request.0));
            println!(
                "Public delegation certificate: {}",
                v["delegation"]["delegation_hex"]
                    .as_str()
                    .ok_or("Missing retained delegation")?
            );
        }
        Ok(())
    }
    fn menu(&mut self) -> Result<()> {
        loop {
            println!(
                "\nRldcoin native wallet | {} | peer sync: {}",
                self.account
                    .as_ref()
                    .map_or("no wallet selected", |a| a.name.as_str()),
                if self.node.peer { "enabled" } else { "offline" }
            );
            println!("1 Create wallet\n2 Select wallet\n3 Balance\n4 Start mining\n5 Stop mining\n6 Send ordinary payment\n7 Resume retained payment\n8 Authorize receipt service (funding miner)\n9 Export retained delegation\n10 Fast payments and channel settlement\n0 Close wallet and local node");
            let choice = text("Choose")?;
            if choice == "0" {
                return self.node.finish();
            }
            let result = match choice.as_str() {
                "1" => self.select(true),
                "2" => self.select(false),
                "3" => self.balances(),
                "4" => (|| {
                    let a = self.selected()?;
                    self.node.refresh()?;
                    self.node
                        .call(json!({"command":"mining_start","reward":a.owner}), None)?;
                    println!("Mining enabled. Rewards use the selected public address; no wallet key is held for mining.");
                    Ok(())
                })(),
                "5" => self
                    .node
                    .call(json!({"command":"mining_stop"}), None)
                    .map(|_| println!("Mining stopped.")),
                "6" => self.transfer(),
                "7" => self.resume(),
                "8" => self.delegation(),
                "10" => self.fast_menu(),
                "9" => (|| {
                    let request = parse_id(&text("Retained signing request")?)?;
                    self.node.refresh()?;
                    let v = self.node.call(
                        json!({"command":"retained_delegation","sign_request":request}),
                        None,
                    )?;
                    println!(
                        "Public delegation certificate: {}",
                        v["delegation"]["delegation_hex"]
                            .as_str()
                            .ok_or("Missing retained delegation")?
                    );
                    Ok(())
                })(),
                _ => Err("Choose a listed action".into()),
            };
            if let Err(e) = result {
                if !self.node.healthy || e == "Input closed" || e.starts_with("Input line too long")
                {
                    return Err(e);
                }
                println!("Action stopped: {e:?}\nRetained state has not been reset. Use Resume payment or controlled recovery when needed.");
            }
        }
    }
}
fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 && args.len() != 8 {
        return Err("Usage: rld-fast-wallet init|open|recover ROOT GENESIS PIN CALLER_HEAD_FILE [PEER_ROOT PEER_HEAD_FILE]".into());
    }
    let program = std::env::current_exe()
        .map_err(fail)?
        .parent()
        .ok_or("Missing wallet executable directory")?
        .join("rld-fast-payment-session");
    let mode = match args[1].as_str() {
        "init" => "create-log-control",
        "open" => "serve-log-control",
        "recover" => "recover-log-control",
        _ => return Err("Choose init, open or recover".into()),
    };
    if args.len() == 8 && args[1] != "open" {
        return Err("Peer options are accepted only with open".into());
    }
    let mut launch = vec![mode.to_string()];
    launch.extend_from_slice(&args[2..6]);
    if args.len() == 8 {
        launch.extend([
            "--peer-root".into(),
            args[6].clone(),
            "--peer-head-file".into(),
            args[7].clone(),
            "--auto-sync".into(),
        ]);
    }
    println!("Pinned network: {}", args[4]);
    let (mut node, ready) = Node::start(&program, &launch)?;
    if args[1] != "open" {
        if ready["request_id"].is_string() {
            println!("Retained request: {}", ready["request_id"]);
        }
        if let Some(certificate) = ready["delegation"]["delegation_hex"].as_str() {
            println!("Public delegation certificate: {certificate}");
        }
        println!(
            "Native state {} completed. Session head: {}",
            args[1],
            hex::encode(node.head.0)
        );
        return node.finish();
    }
    Wallet {
        node,
        account: None,
    }
    .menu()
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Wallet stopped: {e:?}");
        std::process::exit(1);
    }
}
