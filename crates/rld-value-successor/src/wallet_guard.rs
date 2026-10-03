//! Candidate recipient journal coupled to a durable watchtower package.
//! A receipt is returned only after the matching challenge authorization has
//! been published. This does not authenticate live funding or prevent rollback
//! of both local journals without an independent witness.

use crate::{
    chain::{CandidateChain, CandidateEscrowObservation},
    signed_state_hash,
    watchtower::WatchPackage,
    ActionFee, ActionFeeIntent, DisputeAction, Result,
};
use rld_core::{sign_bytes, Amount};
use rld_fast_payments::{
    wallet::RecipientStore, Funding, PaymentOffer, PaymentReceipt, SignedState,
};
use rld_pow::OutPoint;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_WATCH_BYTES: usize = 32_768;

#[derive(Clone, Debug)]
pub struct FeeFunding {
    pub input: OutPoint,
    pub input_amount: Amount,
    pub fee: Amount,
    pub valid_through_height: u128,
}

pub struct GuardedRecipient {
    root: PathBuf,
    _lock: File,
    recipient: RecipientStore,
    funding: Funding,
    receiver: String,
    current: WatchPackage,
    poisoned: bool,
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

fn plain_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = io(fs::symlink_metadata(path))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("unsafe guarded wallet directory".into());
        }
    }
    Ok(())
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_WATCH_BYTES as u64
    {
        return Err("unsafe or oversized watch package".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("watch package is readable by other users".into());
        }
    }
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(MAX_WATCH_BYTES as u64 + 1)
        .read_to_end(&mut bytes))?;
    if bytes.len() > MAX_WATCH_BYTES {
        return Err("watch package exceeded byte bound".into());
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or("missing guarded wallet directory")?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        if io(fs::symlink_metadata(&pending))?.file_type().is_symlink() {
            return Err("unsafe pending watch package".into());
        }
        io(fs::remove_file(&pending))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(&pending))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())?;
    io(fs::rename(&pending, path))?;
    io(io(File::open(dir))?.sync_all())
}

impl GuardedRecipient {
    /// `initial_fee` is required only when creating a new store. Reopening
    /// reads the signed package already on disk and needs no private key.
    pub fn open(
        root: &Path,
        funding: Funding,
        receiver: String,
        initial: SignedState,
        initial_fee: Option<ActionFee>,
    ) -> Result<Self> {
        plain_directory(root)?;
        io(fs::create_dir_all(root))?;
        if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
            io(io(File::open(parent))?.sync_all())?;
        }
        let lock_path = root.join(".guard.lock");
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("unsafe guarded wallet lock".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("guarded wallet already owned: {error}"))?;
        let recipient = RecipientStore::open(
            &root.join("recipient"),
            funding.clone(),
            receiver.clone(),
            initial.clone(),
        )?;
        let path = root.join("watch-package.json");
        let package_exists = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.to_string()),
        };
        let current = if package_exists {
            let bytes = bounded_file(&path)?;
            let package: WatchPackage =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if bytes != serde_json::to_vec(&package).map_err(|error| error.to_string())? {
                return Err("noncanonical watch package".into());
            }
            package
        } else {
            if recipient.latest() != &initial {
                return Err("receipt journal exists without watch package".into());
            }
            let package = WatchPackage {
                funding: funding.clone(),
                state: initial,
                fee: initial_fee.ok_or("new guarded wallet requires initial challenge fee")?,
            };
            let bytes = serde_json::to_vec(&package).map_err(|error| error.to_string())?;
            if bytes.len() > MAX_WATCH_BYTES {
                return Err("watch package too large".into());
            }
            package.validate()?;
            atomic_write(&path, &bytes)?;
            package
        };
        current.validate()?;
        if current.funding != funding || current.fee.intent.owner != receiver {
            return Err("guarded wallet package belongs to another recipient".into());
        }
        let current_seq = current.state.state.sequence;
        let wallet_seq = recipient.latest().state.sequence;
        if current_seq > wallet_seq
            || wallet_seq.saturating_sub(current_seq) > 1
            || (current_seq == wallet_seq && current.state != *recipient.latest())
        {
            return Err("watch package and recipient journal diverged".into());
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            recipient,
            funding,
            receiver,
            current,
            poisoned: false,
        })
    }

    pub fn latest(&self) -> &SignedState {
        self.recipient.latest()
    }

    pub fn watch_package(&self) -> &WatchPackage {
        &self.current
    }

    pub fn accept_offer(
        &mut self,
        chain: &CandidateChain,
        minimum_confirmations: u128,
        require_finality: bool,
        offer: PaymentOffer,
        receiver_secret: &str,
        fee: FeeFunding,
    ) -> Result<PaymentReceipt> {
        let observation = if require_finality {
            CandidateEscrowObservation::new_finalized(chain, minimum_confirmations)?
        } else {
            CandidateEscrowObservation::new(chain, minimum_confirmations)?
        };
        observation.verify_payment_readiness(
            &self.funding,
            &self.receiver,
            &fee.input,
            fee.input_amount,
            fee.fee,
            fee.valid_through_height,
        )?;
        self.accept_offer_unchecked(offer, receiver_secret, fee)
    }

    fn accept_offer_unchecked(
        &mut self,
        offer: PaymentOffer,
        receiver_secret: &str,
        fee: FeeFunding,
    ) -> Result<PaymentReceipt> {
        if self.poisoned {
            return Err("guarded wallet stopped after storage failure".into());
        }
        let wallet_seq = self.recipient.latest().state.sequence;
        let watched_seq = self.current.state.state.sequence;
        if watched_seq < wallet_seq && offer.proposed.sequence != wallet_seq {
            return Err("unprotected receipt requires identical retry".into());
        }
        let expected = offer.cosign(&self.funding, receiver_secret)?;
        expected.verify(&self.funding, &self.receiver)?;
        let change = fee
            .input_amount
            .checked_sub(fee.fee)
            .map_err(|error| error.to_string())?;
        let intent = ActionFeeIntent {
            chain_id: self.funding.chain_id,
            action: DisputeAction::Challenge,
            channel: self.funding.id()?,
            signed_state: signed_state_hash(&expected.updated)?,
            input: fee.input,
            owner: self.receiver.clone(),
            fee: fee.fee,
            change,
            valid_through_height: fee.valid_through_height,
        };
        let package = WatchPackage {
            funding: self.funding.clone(),
            state: expected.updated.clone(),
            fee: ActionFee {
                owner_signature: sign_bytes(receiver_secret, &intent.signing_bytes()?)?,
                intent,
            },
        };
        package.validate()?;
        let bytes = serde_json::to_vec(&package).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_WATCH_BYTES {
            return Err("watch package too large".into());
        }
        let receipt = self.recipient.accept_offer(offer, receiver_secret)?;
        if receipt != expected {
            return Err("recipient journal returned a conflicting receipt".into());
        }
        let next_seq = package.state.state.sequence;
        if next_seq == watched_seq {
            if package != self.current {
                return Err("conflicting watch package for completed receipt".into());
            }
        } else if watched_seq.checked_add(1) == Some(next_seq) {
            if let Err(error) = atomic_write(&self.root.join("watch-package.json"), &bytes) {
                self.poisoned = true;
                return Err(error);
            }
            self.current = package;
        } else {
            return Err("watch package sequence gap".into());
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
