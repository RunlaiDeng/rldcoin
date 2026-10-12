//! Explicit no-value Earth fixture launcher and bounded loopback HTTP adapters.
use anyhow::{ensure, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(Clone, ValueEnum, PartialEq)]
enum Mode {
    Source,
    Destination,
    Observer,
}
#[derive(Subcommand)]
enum Action {
    Run {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        mode: Mode,
        #[arg(long)]
        expected_implementation: String,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        no_mining: bool,
        #[arg(long, default_value_t = 10000)]
        mine_interval_ms: u64,
    },
    Wallet {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        expected_implementation: String,
    },
    Gateway,
    Bridge {
        #[arg(long)]
        region: String,
        #[arg(long)]
        port: u16,
    },
}
fn document(path: &Path) -> Result<Value> {
    ensure!(
        fs::symlink_metadata(path)?.is_file() && !path.is_symlink(),
        "fixture input must be regular"
    );
    ensure!(
        fs::metadata(path)?.len() <= 8 * 1024 * 1024,
        "fixture metadata byte bound"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn pins(root: &Path, expected: &str) -> Result<Value> {
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "independent implementation SHA256 required"
    );
    let pins = document(&root.join("records/testnet.json"))?;
    for (key, value) in [
        ("test_only", true),
        ("has_monetary_value", false),
        ("mainnet_authorized", false),
        ("old_balances_migrate", false),
    ] {
        ensure!(pins[key] == value, "fixture no-value policy differs");
    }
    ensure!(
        pins["implementation_source"] == expected
            && pins["initial_source_height"] == "0"
            && pins["initial_source_issued"] == "0",
        "fixture implementation or zero issuance differs"
    );
    Ok(pins)
}
fn executable(root: &Path, name: &str) -> Result<PathBuf> {
    use std::io::Read;
    let path = root.join("bin").join(name);
    ensure!(
        !path.is_symlink() && fs::symlink_metadata(&path)?.is_file(),
        "fixture executable must be regular"
    );
    let expected = document(&root.join("binary-hashes.json"))?;
    let mut file = fs::File::open(&path)?;
    let mut hash = Sha256::new();
    let mut total = 0usize;
    let mut chunk = [0; 65536];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        total += n;
        ensure!(total <= 128 * 1024 * 1024, "fixture binary byte bound");
        hash.update(&chunk[..n]);
    }
    ensure!(
        expected[name] == hex::encode(hash.finalize()),
        "fixture executable differs from independently retained bytes"
    );
    Ok(path)
}
fn run(
    root: &Path,
    mode: Mode,
    expected: &str,
    peer: Option<String>,
    no_mining: bool,
    interval: u64,
) -> Result<()> {
    ensure!(
        (1000..=600000).contains(&interval),
        "test mining polling interval outside resource budget"
    );
    let root = root.canonicalize()?;
    let pins = pins(&root, expected)?;
    let records = root.join("records");
    let data = root.join("data");
    if !data.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&data)?;
    }
    ensure!(
        !data.is_symlink() && fs::metadata(&data)?.is_dir(),
        "fixture data directory unsafe"
    );
    let binary = executable(
        &root,
        if mode == Mode::Destination {
            "rld-earth-destination-node"
        } else {
            "rld-earth-node"
        },
    )?;
    let mut command = std::process::Command::new(binary);
    if mode != Mode::Destination {
        command.arg("run-adopted");
    }
    for (flag, name) in [
        ("genesis", "genesis.json"),
        ("history", "history.json"),
        ("adoption", "adoption.json"),
        ("transition-preview", "transition-preview.json"),
        ("earth-adoption", "earth-adoption.json"),
    ] {
        command.arg(format!("--{flag}")).arg(records.join(name));
    }
    for (flag, key) in [
        ("manifest-pin", "manifest_pin"),
        ("accept-adoption", "adoption_id"),
        ("pinned-v1-source", "implementation_source"),
        ("accept-transition-preview", "preview_id"),
        ("accept-earth-adoption", "earth_adoption_id"),
    ] {
        command
            .arg(format!("--{flag}"))
            .arg(pins[key].as_str().context("required fixture pin")?);
    }
    let name = match mode {
        Mode::Source => "source",
        Mode::Destination => "destination",
        Mode::Observer => "observer",
    };
    command
        .arg("--v1-data-dir")
        .arg(data.join(format!("{name}-v1")));
    if mode == Mode::Destination {
        command
            .arg("--source-candidate-dir")
            .arg(data.join("destination-source"))
            .args(["--source-node", "http://127.0.0.1:48500"])
            .arg("--destination-context")
            .arg(records.join("destination-context.json"))
            .arg("--destination-authorization")
            .arg(records.join("destination-authorization.json"))
            .arg("--accept-destination-authorization")
            .arg(
                pins["destination_authorization_id"]
                    .as_str()
                    .context("destination authorization")?,
            )
            .arg("--destination-signer")
            .arg(
                pins["destination_signer"]
                    .as_str()
                    .context("destination signer")?,
            )
            .arg("--destination-dir")
            .arg(data.join("destination"))
            .args(["--listen", "127.0.0.1:48510"]);
    } else {
        command.arg("--data-dir").arg(data.join(name)).args([
            "--listen",
            if mode == Mode::Observer {
                "127.0.0.1:48520"
            } else {
                "127.0.0.1:48500"
            },
        ]);
        if mode == Mode::Observer {
            ensure!(
                peer.as_deref() == Some("http://127.0.0.1:48530"),
                "observer requires bounded private loopback bridge"
            );
            command.args(["--peer", "http://127.0.0.1:48530"]);
        } else if !no_mining {
            command
                .arg("--mine-to")
                .arg(pins["miner"].as_str().context("fixture miner")?)
                .arg("--mine-interval-ms")
                .arg(interval.to_string());
        }
    }
    use std::os::unix::process::CommandExt;
    Err(command.exec().into())
}
fn wallet(root: &Path, expected: &str) -> Result<()> {
    let root = root.canonicalize()?;
    let pins = pins(&root, expected)?;
    let binary = executable(&root, "rld-earth-wallet")?;
    let records = root.join("records");
    for (source, target) in [
        ("adoption.json", "pow-adoption.json"),
        ("earth-adoption.json", "value-adoption.json"),
        ("transition-preview.json", "preview.json"),
    ] {
        let bytes = fs::read(records.join(source))?;
        let target = records.join(target);
        if target.exists() {
            ensure!(
                !target.is_symlink() && fs::read(&target)? == bytes,
                "existing wallet record differs"
            );
        } else {
            fs::write(target, bytes)?;
        }
    }
    let config = records.join("wallet-destination.json");
    let destination = json!({"context":records.join("destination-context.json"),"authorization":records.join("destination-authorization.json"),"node":"http://127.0.0.1:48531"});
    for (path, value) in [
        (
            records.join("pins.json"),
            json!({"manifest_pin":pins["manifest_pin"],"pow_adoption_id":pins["adoption_id"]}),
        ),
        (config.clone(), destination),
    ] {
        if path.exists() {
            ensure!(document(&path)? == value, "existing wallet config differs");
        } else {
            fs::write(path, serde_json::to_vec(&value)?)?;
        }
    }
    let mut command = std::process::Command::new(binary);
    command
        .arg("--records")
        .arg(records)
        .arg("--data")
        .arg(root.join("wallet"))
        .args(["--node", "http://127.0.0.1:48520", "--port", "48550"])
        .arg("--destination-config")
        .arg(config)
        .arg("--accept-destination-authorization")
        .arg(
            pins["destination_authorization_id"]
                .as_str()
                .context("destination authorization")?,
        )
        .arg("--destination-signer")
        .arg(
            pins["destination_signer"]
                .as_str()
                .context("destination signer")?,
        );
    use std::os::unix::process::CommandExt;
    Err(command.exec().into())
}
fn allowed(region: &str, method: &str, path: &str) -> bool {
    let id = |v: &str| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    match (region, method) {
        ("earth", "GET") => {
            ["status", "continuity", "finality"].contains(&path)
                || path.strip_prefix("escrows/").is_some_and(id)
                || path.strip_prefix("commands/").is_some_and(id)
        }
        ("earth", "POST") => ["template", "blocks", "sync", "pending", "commands"].contains(&path),
        ("earth-destination", "GET") => {
            path == "status" || path.strip_prefix("balance/").is_some_and(id)
        }
        ("earth-destination", "POST") => {
            ["template", "blocks", "sync", "receipts", "verify-receipt"].contains(&path)
        }
        _ => false,
    }
}
#[derive(Clone)]
struct App {
    client: reqwest::Client,
    slots: Arc<Semaphore>,
    bridge: Option<String>,
}
fn reply(status: StatusCode, value: Value, public: bool) -> Response {
    let mut value = if value.is_object() {
        value
    } else {
        json!({"result":value,"testnet_result_envelope":true})
    };
    if public {
        for (key, bool) in [
            ("test_only", true),
            ("has_monetary_value", false),
            ("mainnet_authorized", false),
            ("live_rld", false),
        ] {
            value[key] = json!(bool);
        }
    }
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONNECTION, "close"),
        ],
        Body::from(value.to_string()),
    )
        .into_response()
}
async fn dispatch(State(app): State<App>, request: Request) -> Response {
    let public = app.bridge.is_none();
    let Ok(_permit) = app.slots.clone().try_acquire_owned() else {
        return reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Test gateway busy"}),
            public,
        );
    };
    let result = async {
        ensure!(request.uri().query().is_none(), "unknown testnet route");
        let path = request.uri().path().to_owned();
        let prefix = if public { "/v1/testnet/" } else { "/v1/" };
        let suffix = path.strip_prefix(prefix).context("unknown testnet route")?;
        let (region, path) = suffix.split_once('/').context("unknown testnet route")?;
        let method = request.method().as_str().to_owned();
        ensure!(
            allowed(region, &method, path) && app.bridge.as_deref().is_none_or(|r| r == region),
            "unknown testnet route"
        );
        let headers = request.headers();
        ensure!(
            !headers.contains_key(header::TRANSFER_ENCODING),
            "chunked test requests refused"
        );
        if let Some(size) = headers.get(header::CONTENT_LENGTH) {
            ensure!(
                size.to_str()?.parse::<usize>()? <= 3 * 1024 * 1024,
                "test request byte bound"
            );
        }
        let url = if public {
            format!(
                "http://127.0.0.1:{}/v1/{region}/{path}",
                if region == "earth" { 48500 } else { 48510 }
            )
        } else {
            format!("https://api.rldcoin.com/v1/testnet/{region}/{path}")
        };
        let body = tokio::time::timeout(
            Duration::from_secs(15),
            to_bytes(request.into_body(), 3 * 1024 * 1024),
        )
        .await??;
        let mut upstream = app
            .client
            .request(method.parse()?, url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body)
            .send()
            .await?;
        let status = upstream.status();
        let mut raw = Vec::new();
        while let Some(chunk) = upstream.chunk().await? {
            ensure!(
                raw.len() + chunk.len() <= 8 * 1024 * 1024,
                "test response byte bound"
            );
            raw.extend_from_slice(&chunk);
        }
        let mut value: Value = serde_json::from_slice(&raw)?;
        if !public {
            for (key, bool) in [
                ("test_only", true),
                ("has_monetary_value", false),
                ("mainnet_authorized", false),
                ("live_rld", false),
            ] {
                ensure!(value[key] == bool, "upstream no-value policy differs");
                value
                    .as_object_mut()
                    .context("upstream object")?
                    .remove(key);
            }
            if value["testnet_result_envelope"] == true {
                let map = value.as_object_mut().context("result envelope")?;
                map.remove("testnet_result_envelope");
                ensure!(
                    map.len() == 1 && map.contains_key("result"),
                    "testnet result envelope differs"
                );
                value = map.remove("result").context("test result")?;
            }
            if ["status", "continuity"].contains(&path) && status.is_success() {
                value["live_rld"] = json!(true);
            }
        }
        Ok::<_, anyhow::Error>((status, value))
    }
    .await;
    match result {
        Ok((status, value)) => reply(status, value, public),
        Err(_) => reply(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"Test node unavailable or request refused"}),
            public,
        ),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().action {
        Action::Run {
            root,
            mode,
            expected_implementation,
            peer,
            no_mining,
            mine_interval_ms,
        } => run(
            &root,
            mode,
            &expected_implementation,
            peer,
            no_mining,
            mine_interval_ms,
        ),
        Action::Wallet {
            root,
            expected_implementation,
        } => wallet(&root, &expected_implementation),
        action => {
            let (port, bridge) = match action {
                Action::Gateway => (48540, None),
                Action::Bridge { region, port } => {
                    ensure!(
                        ["earth", "earth-destination"].contains(&region.as_str()) && port != 0,
                        "bridge region/port invalid"
                    );
                    (port, Some(region))
                }
                _ => unreachable!(),
            };
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(25))
                .build()?;
            let state = App {
                client,
                slots: Arc::new(Semaphore::new(if bridge.is_some() { 8 } else { 16 })),
                bridge,
            };
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            axum::serve(
                listener,
                Router::new().fallback(any(dispatch)).with_state(state),
            )
            .await?;
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_are_exact_and_hex_is_lowercase() {
        assert!(allowed("earth", "GET", "status"));
        assert!(allowed(
            "earth",
            "GET",
            &format!("escrows/{}", "ab".repeat(32))
        ));
        for path in [
            "status/../template",
            "status?debug=true",
            "escrows/short",
            "status/",
        ] {
            assert!(!allowed("earth", "GET", path));
        }
        assert!(!allowed("earth-destination", "POST", "commands"));
        assert!(!allowed("earth", "DELETE", "blocks"));
        assert!(!allowed("mainnet", "GET", "status"));
    }
}
