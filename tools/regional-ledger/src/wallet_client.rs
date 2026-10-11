//! Separate caller-head persistence for the loopback ground wallet client.
//! A saved head is caller custody, not independent freshness or ledger authority.
use crate::{require, storage::Store, wallet_agent, Hash, Result, MAX_BYTES};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

pub const FORMAT: &str = "RLD-REGIONAL-WALLET-APP-V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub currency: Hash,
    pub region: Hash,
    pub owner: String,
    pub wallet_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub prepared: wallet_agent::Prepared,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub format: String,
    pub binding: Binding,
    pub head: Option<Hash>,
    pub pending: Option<Pending>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    pub previous: State,
    pub proposed: State,
}

#[derive(Debug, Serialize)]
pub struct Recovery {
    pub state: State,
    pub recovery_notice: Option<&'static str>,
}

pub struct Client {
    root: PathBuf,
    binding: Binding,
    _lock: File,
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

pub(crate) fn private_metadata(file: &File) -> Result<()> {
    let meta = file.metadata().map_err(io)?;
    require(meta.is_file(), "caller state must be a regular file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
            "private caller file permissions or owner invalid",
        )?;
    }
    Ok(())
}

pub(crate) fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    options
}

pub(crate) fn private_read(path: &Path) -> Result<Vec<u8>> {
    private_read_with_limit(path, MAX_BYTES)
}

pub(crate) fn private_read_with_limit(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(io)?;
    require(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= limit as u64,
        "private caller file type or byte bound invalid",
    )?;
    let file = options().read(true).open(path).map_err(io)?;
    private_metadata(&file)?;
    require(
        file.metadata().map_err(io)?.len() <= limit as u64,
        "caller state byte bound",
    )?;
    let mut raw = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(io)?;
    require(raw.len() <= limit, "caller state byte bound")?;
    Ok(raw)
}

pub(crate) fn private_path(path: &Path, must_exist: bool) -> Result<()> {
    require(
        path.is_absolute() && !path.components().any(|p| matches!(p, Component::ParentDir)),
        "private path must be absolute without parent traversal",
    )?;
    for (index, part) in path.ancestors().enumerate() {
        match fs::symlink_metadata(part) {
            Ok(meta) => require(
                !meta.file_type().is_symlink() && meta.is_dir(),
                "private directory symlink or type invalid",
            )?,
            Err(e) if index == 0 && !must_exist && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(())
}

/// Preserve Python's sorted ASCII JSON bytes, including non-ASCII wallet paths.
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical_with_limit(value, MAX_BYTES)
}

/// Separate companion archives use their existing bound; ledger callers keep MAX_BYTES.
pub(crate) fn canonical_with_limit<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    fn python_float(number: &serde_json::Number) -> Result<String> {
        // Python and Ryu use shortest round-trip digits; Python additionally
        // fixes the decimal/scientific cutover and signed two-digit exponent.
        let text = number.to_string();
        let (sign, unsigned) = text
            .strip_prefix('-')
            .map(|s| ("-", s))
            .unwrap_or(("", text.as_str()));
        let (mantissa, exponent) = unsigned.split_once('e').unwrap_or((unsigned, "0"));
        let exponent: i32 = exponent.parse().map_err(|_| "JSON float exponent")?;
        let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
        let all = mantissa.replace('.', "");
        let leading = all.bytes().take_while(|b| *b == b'0').count();
        if leading == all.len() {
            return Ok(format!("{sign}0.0"));
        }
        let digits = all[leading..].trim_end_matches('0');
        let power = point + exponent - leading as i32 - 1;
        if !(-4..16).contains(&power) {
            let tail = if digits.len() > 1 {
                format!(".{}", &digits[1..])
            } else {
                String::new()
            };
            return Ok(format!(
                "{sign}{}{tail}e{}{:02}",
                &digits[..1],
                if power < 0 { "-" } else { "+" },
                power.abs()
            ));
        }
        let point = power + 1;
        if point <= 0 {
            return Ok(format!("{sign}0.{}{digits}", "0".repeat((-point) as usize)));
        }
        let point = point as usize;
        if point >= digits.len() {
            return Ok(format!(
                "{sign}{digits}{}.0",
                "0".repeat(point - digits.len())
            ));
        }
        Ok(format!("{sign}{}.{}", &digits[..point], &digits[point..]))
    }
    fn sorted(value: &serde_json::Value, out: &mut String, limit: usize) -> Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                out.push('{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).map_err(|e| e.to_string())?);
                    out.push(':');
                    sorted(&map[key], out, limit)?;
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index != 0 {
                        out.push(',');
                    }
                    sorted(item, out, limit)?;
                }
                out.push(']');
            }
            serde_json::Value::Number(number) if number.is_f64() => {
                out.push_str(&python_float(number)?)
            }
            _ => out.push_str(&serde_json::to_string(value).map_err(|e| e.to_string())?),
        }
        require(out.len() <= limit, "caller state byte bound")
    }
    let mut text = String::new();
    sorted(
        &serde_json::to_value(value).map_err(|e| e.to_string())?,
        &mut text,
        limit,
    )?;
    let mut out = String::new();
    for ch in text.chars() {
        if ch as u32 >= 0x7f {
            use std::fmt::Write;
            for unit in ch.encode_utf16(&mut [0; 2]) {
                write!(&mut out, "\\u{unit:04x}").map_err(|e| e.to_string())?;
            }
        } else {
            out.push(ch);
        }
        require(out.len() <= limit, "caller state byte bound")?;
    }
    Ok(out.into_bytes())
}

impl Client {
    pub fn lock(root: &Path, wallet: &Path, owner: String, node: &Store) -> Result<Self> {
        require(
            cfg!(unix),
            "native caller custody requires Unix no-follow file operations",
        )?;
        private_path(root, true)?;
        private_path(wallet, false)?;
        require(
            !root.starts_with(wallet) && !wallet.starts_with(root),
            "caller head must be separate from wallet directory",
        )?;
        crate::verification_keys::validate_ed25519_public_key(&owner)?;
        let lock = options()
            .read(true)
            .write(true)
            .create(true)
            .open(root.join(".state.lock"))
            .map_err(io)?;
        private_metadata(&lock)?;
        lock.try_lock().map_err(|e| e.to_string())?;
        Ok(Self {
            root: root.to_owned(),
            binding: Binding {
                currency: node.trust.currency()?,
                region: node.chain.region,
                owner,
                wallet_dir: wallet.to_str().ok_or("wallet path is not UTF-8")?.into(),
            },
            _lock: lock,
        })
    }

    fn validate(&self, state: &State) -> Result<()> {
        require(
            state.format == FORMAT && state.binding == self.binding,
            "caller-head binding differs",
        )?;
        if let Some(pending) = &state.pending {
            require(
                state.head == Some(pending.prepared.wallet_head)
                    && pending.prepared.draft.pin.currency == self.binding.currency
                    && pending.prepared.draft.pin.region == self.binding.region
                    && pending.prepared.draft.request.owner == self.binding.owner,
                "pending request differs from caller head or binding",
            )?;
        }
        Ok(())
    }

    pub fn read(&self) -> Result<State> {
        let raw = private_read(&self.root.join("wallet-client.json"))?;
        let state: State = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        self.validate(&state)?;
        require(canonical(&state)? == raw, "noncanonical caller JSON")?;
        Ok(state)
    }

    fn persist(&self, state: &State) -> Result<()> {
        self.validate(state)?;
        let raw = canonical(state)?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let temporary = self.root.join(format!(".write-{}", hex::encode(random)));
        let mut file = options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io)?;
        private_metadata(&file)?;
        file.write_all(&raw).map_err(io)?;
        file.sync_all().map_err(io)?;
        // A failed publication retains the residue. It is never promoted as head.
        fs::rename(&temporary, self.root.join("wallet-client.json")).map_err(io)?;
        File::open(&self.root).map_err(io)?.sync_all().map_err(io)
    }

    fn wallet(&self, node: &Store) -> Result<wallet_agent::Agent> {
        let agent = wallet_agent::Agent::open(Path::new(&self.binding.wallet_dir), node)?;
        require(
            agent.journal.binding.owner == self.binding.owner
                && agent.journal.binding.currency == self.binding.currency
                && agent.journal.binding.region == self.binding.region,
            "caller binding differs from native wallet custody",
        )?;
        Ok(agent)
    }

    pub fn open(&self, node: &Store, expected: Option<Hash>) -> Result<State> {
        let mut state = match fs::symlink_metadata(self.root.join("wallet-client.json")) {
            Ok(_) => self.read()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(head) = expected {
                    self.wallet(node)?.view(node, head)?;
                } else {
                    require(
                        !Path::new(&self.binding.wallet_dir).exists(),
                        "existing wallet needs separately retained latest head",
                    )?;
                }
                let state = State {
                    format: FORMAT.into(),
                    binding: self.binding.clone(),
                    head: expected,
                    pending: None,
                };
                self.persist(&state)?;
                state
            }
            Err(e) => return Err(io(e)),
        };
        if let Some(head) = expected {
            require(
                state.head.is_none() || state.head == Some(head),
                "explicit caller head differs from retained state",
            )?;
            if state.head.is_none() {
                self.wallet(node)?.view(node, head)?;
                state.head = Some(head);
                self.persist(&state)?;
            }
        }
        if state.pending.is_none() {
            if let Some(head) = state.head {
                self.wallet(node)?.view(node, head)?;
            } else {
                require(
                    !Path::new(&self.binding.wallet_dir).exists(),
                    "interrupted wallet initialization needs explicit verified caller head",
                )?;
            }
        }
        Ok(state)
    }

    /// Calculate recovery over full native custody. Caller publication is separate.
    pub fn reconcile(&self, node: &Store, expected: State) -> Result<Recovery> {
        let state = self.read()?;
        require(state == expected, "caller state changed before recovery")?;
        let Some(pending) = &state.pending else {
            return Ok(Recovery {
                state,
                recovery_notice: None,
            });
        };
        let head = state
            .head
            .ok_or("pending caller review lacks wallet head")?;
        let agent = self.wallet(node)?;
        let (next_head, notice) = match agent.recover_prepared(node, &pending.prepared) {
            Ok(signed) => {
                require(
                    signed.recovered_exact_retry,
                    "restart must recover existing signature",
                )?;
                (
                    signed.wallet_head,
                    "已恢复上次保存的签名和输入预留，没有再次签名。",
                )
            }
            Err(_) => {
                // Complete native replay at the original exact head proves that
                // no new wallet record exists. An unknown/changed head refuses.
                agent.view(node, head)?;
                (head, "上次确认未生成签名；请重新预览并确认。")
            }
        };
        let mut proposed = state;
        proposed.head = Some(next_head);
        proposed.pending = None;
        Ok(Recovery {
            state: proposed,
            recovery_notice: Some(notice),
        })
    }

    pub fn store(&self, node: &Store, transition: Transition) -> Result<State> {
        let previous = self.read()?;
        require(
            previous == transition.previous,
            "caller state changed before publication",
        )?;
        let proposed = transition.proposed;
        self.validate(&proposed)?;
        if previous == proposed {
            return Ok(proposed);
        }
        let agent = self.wallet(node)?;
        match (
            previous.head,
            &previous.pending,
            proposed.head,
            &proposed.pending,
        ) {
            (None, None, Some(head), None) => {
                agent.view(node, head)?;
            }
            (Some(head), None, Some(next), Some(pending)) if head == next => {
                agent.view(node, head)?;
                // A clicked review may have become stale since preparation.
                // Retain it as user consent only; ordinary signing must still
                // recheck the complete current draft and all input authority.
                require(
                    pending.prepared.review_commitment
                        == crate::id("wallet-reviewed-draft", &pending.prepared.draft)?,
                    "pending review commitment differs from complete draft",
                )?;
            }
            (Some(head), Some(pending), Some(next), None) => {
                match agent.recover_prepared(node, &pending.prepared) {
                    Ok(signed) => require(
                        signed.wallet_head == next,
                        "caller head differs from exact retained response",
                    )?,
                    Err(_) if next == head => {
                        agent.view(node, head)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            _ => return Err("caller transition lacks exact native authorization".into()),
        }
        self.persist(&proposed)?;
        Ok(proposed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_python_ascii_bytes_preserve_unicode_order_and_control_escaping() {
        let value = serde_json::json!({"z": "钱包🚀\u{7f}\n", "a": ["é", "\\\""]});
        assert_eq!(
            canonical(&value).unwrap(),
            br#"{"a":["\u00e9","\\\""],"z":"\u94b1\u5305\ud83d\ude80\u007f\n"}"#
        );
    }
    #[test]
    fn canonical_python_float_cutovers_preserve_historical_transport_bytes() {
        let value = serde_json::json!([1.0, -0.0, 1e-5, 1e-4, 1e15, 1e16, 5e-324, 1.23456789]);
        assert_eq!(
            canonical(&value).unwrap(),
            b"[1.0,-0.0,1e-05,0.0001,1000000000000000.0,1e+16,5e-324,1.23456789]"
        );
    }
}
