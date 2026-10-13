//! Independent BFT caller custody for ordinary and complete-origin companions.
//! No initialization, private key, first-sign or transport acknowledgment authority.
use crate::{bft, require, storage::Store, wallet_client as files, Hash, Result, MAX_BYTES};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

pub const FORMAT: &str = "RLD-REGIONAL-BFT-NODE-V1";
pub const ORIGIN_FORMAT: &str = "RLD-REGIONAL-BFT-ORIGIN-NODE-V8";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub format: String,
    pub binding: bft::Binding,
    pub head: Hash,
    pub pending: Option<bft::Request>,
    pub outbox: Option<bft::Message>,
}
pub struct Transition {
    pub previous_sha256: Hash,
    pub proposed: State,
}

/// Reject duplicate keys and any fields/types lost by the typed decoder.
pub fn decode<T: DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    require(raw.len() <= MAX_BYTES, "BFT caller input byte bound")?;
    let value = crate::wallet_http::decode_unique(raw)?;
    let typed = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    require(
        serde_json::to_value(&typed).map_err(|e| e.to_string())? == value,
        "BFT caller JSON is not exact typed state",
    )?;
    Ok(typed)
}

pub struct Client {
    path: PathBuf,
    signer: PathBuf,
    binding: bft::Binding,
    format: String,
    _lock: File,
}
impl Client {
    pub fn lock(
        path: &Path,
        signer: &Path,
        key: String,
        format: String,
        node: &Store,
    ) -> Result<Self> {
        require(
            cfg!(unix),
            "BFT caller custody requires Unix private file operations",
        )?;
        let parent = path.parent().ok_or("BFT caller file parent required")?;
        files::private_path(parent, true)?;
        files::private_path(signer, true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for directory in [parent, signer] {
                let meta = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
                require(
                    meta.uid() == unsafe { libc::getuid() } && meta.mode() & 0o077 == 0,
                    "BFT caller/signer directory permissions or owner invalid",
                )?;
            }
        }
        require(
            path.is_absolute()
                && path.file_name().is_some()
                && ![".bft-client.lock", ".bft-runtime.lock"]
                    .iter()
                    .any(|n| path.file_name() == Some(std::ffi::OsStr::new(n))),
            "BFT caller file path invalid",
        )?;
        require(
            !parent.starts_with(signer)
                && !signer.starts_with(parent)
                && !parent.starts_with(node.directory())
                && !node.directory().starts_with(parent),
            "BFT caller head must be separate from signer and ledger",
        )?;
        crate::verification_keys::validate_ed25519_public_key(&key)?;
        let rules = &node.trust.region(node.chain.region)?.rules;
        require(
            (format == FORMAT && rules != bft::JOINT_RULES && rules != bft::ROLE_RULES)
                || (format == ORIGIN_FORMAT && rules == crate::paged_bft::ORIGIN_NETWORK_RULES),
            "BFT caller runtime/admission profile differs",
        )?;
        let lock = files::options()
            .read(true)
            .write(true)
            .create(true)
            .open(parent.join(".bft-client.lock"))
            .map_err(|e| e.to_string())?;
        files::private_metadata(&lock)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                lock.metadata().map_err(|e| e.to_string())?.nlink() == 1,
                "BFT caller lock hard link refuses",
            )?;
        }
        lock.try_lock().map_err(|e| e.to_string())?;
        Ok(Self {
            path: path.into(),
            signer: signer.into(),
            format,
            binding: bft::Binding {
                currency: node.trust.currency()?,
                region: node.chain.region,
                key,
            },
            _lock: lock,
        })
    }
    fn validate(&self, state: &State) -> Result<()> {
        require(
            state.format == self.format
                && state.binding == self.binding
                && state.head != Hash::ZERO,
            "BFT external caller-head binding differs",
        )?;
        require(
            state.pending.is_none() || state.outbox.is_none(),
            "BFT caller pending and outbox overlap",
        )
    }
    pub fn read(&self) -> Result<State> {
        let raw = files::private_read(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            require(
                fs::symlink_metadata(&self.path)
                    .map_err(|e| e.to_string())?
                    .nlink()
                    == 1,
                "BFT caller file hard link refuses",
            )?;
        }
        let state: State = decode(&raw)?;
        self.validate(&state)?;
        require(
            files::canonical(&state)? == raw,
            "BFT caller file must retain canonical JSON bytes",
        )?;
        Ok(state)
    }
    fn inspect(&self, node: &Store) -> Result<bft::Agent> {
        let (agent, _) = bft::Agent::inspect_with_status(&self.signer, node)?;
        require(
            agent.journal.binding == self.binding,
            "BFT native signer binding differs from caller",
        )?;
        Ok(agent)
    }
    fn persist(&self, state: &State) -> Result<()> {
        self.validate(state)?;
        let raw = files::canonical(state)?;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let parent = self.path.parent().ok_or("BFT caller parent absent")?;
        let temp = parent.join(format!(".write-{}", hex::encode(random)));
        let mut file = files::options()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        files::private_metadata(&file)?;
        file.write_all(&raw).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        // Interrupted residue is retained and never promoted as caller authority.
        fs::rename(&temp, &self.path).map_err(|e| e.to_string())?;
        File::open(parent)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())
    }
    pub fn store(&self, node: &Store, transition: Transition) -> Result<State> {
        let old = self.read()?;
        require(
            Hash(Sha256::digest(files::canonical(&old)?).into()) == transition.previous_sha256,
            "BFT caller state changed before publication",
        )?;
        let next = transition.proposed;
        self.validate(&next)?;
        if old == next {
            return Ok(next);
        }
        if let (Some(request), None, None, _) =
            (&old.pending, &old.outbox, &next.pending, &next.outbox)
        {
            // One complete ordinary replay observes the exact original response.
            // It retains the signer lock and refuses incomplete publication;
            // this is neither recover-only publication nor a first-sign path.
            let (agent, status, response) =
                bft::Agent::inspect_with_response_status(&self.signer, node, request, old.head)?;
            require(
                status.binding == self.binding,
                "BFT native response binding differs from caller",
            )?;
            match response {
                Some(signed) => require(
                    signed.recovered_exact_retry
                        && signed.head == next.head
                        && next.outbox.as_ref() == Some(&signed.message),
                    "BFT caller transition differs from exact retained response",
                )?,
                None => require(
                    status.head == old.head && next.head == old.head && next.outbox.is_none(),
                    "BFT unsigned pending clear requires unchanged native/caller head",
                )?,
            }
            self.persist(&next)?;
            drop(agent);
            return Ok(next);
        }
        if let (None, Some(message), None, None) =
            (&old.pending, &old.outbox, &next.pending, &next.outbox)
        {
            require(
                old.head == next.head,
                "BFT outbox clear cannot change the caller head",
            )?;
            let (agent, status, messages) =
                bft::Agent::inspect_with_retained_status(&self.signer, node)?;
            require(
                status.binding == self.binding
                    && status.head == old.head
                    && messages.contains(message),
                "BFT outbox clear requires exact retained signed response/head",
            )?;
            // Complete native envelope validation and durable runtime retention
            // precede this call. Clearing caller outbox acknowledges neither
            // transport custody nor destination acceptance.
            self.persist(&next)?;
            drop(agent);
            return Ok(next);
        }
        let agent = self.inspect(node)?;
        match (&old.pending, &old.outbox, &next.pending, &next.outbox) {
            (None, None, Some(_), None) if old.head == next.head => {
                require(
                    agent.head()? == old.head,
                    "BFT signer differs from separately retained caller head",
                )?;
                // Retain consent before signing; actual sign rechecks current context.
            }
            _ => return Err("BFT caller transition lacks exact native authorization".into()),
        }
        self.persist(&next)?;
        Ok(next)
    }
    /// Calculate recovery only. Exact caller publication is a separate transition.
    pub fn reconcile(&self, node: &Store, expected: State) -> Result<State> {
        let old = self.read()?;
        require(old == expected, "BFT caller state changed before recovery")?;
        let request = old
            .pending
            .clone()
            .ok_or("BFT caller has no pending request")?;
        let recovered =
            if crate::paged_bft::is_profile(&node.trust.region(node.chain.region)?.rules) {
                bft::Agent::recover_response(&self.signer, node, request.clone(), old.head)
            } else {
                let mut agent = bft::Agent::open(&self.signer, node)?;
                require(
                    agent.journal.binding == self.binding,
                    "BFT native recovery binding differs",
                )?;
                if agent.contains_request(node, &request)? {
                    agent.sign(node, request, None, old.head)
                } else {
                    Err("BFT recovery cannot first-sign".into())
                }
            };
        let mut next = old.clone();
        match recovered {
            Ok(signed) => {
                let agent = self.inspect(node)?;
                require(
                    signed.recovered_exact_retry && agent.head()? == signed.head,
                    "BFT recovered response differs from current exact native head",
                )?;
                next.head = signed.head;
                next.outbox = Some(signed.message);
            }
            Err(_) => require(
                self.inspect(node)?.head()? == old.head,
                "BFT signer differs from separately retained caller head; pending preserved",
            )?,
        }
        next.pending = None;
        Ok(next)
    }
}
