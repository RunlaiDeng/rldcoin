//! Durable local receipt journal for the candidate direct-channel model.
//!
//! It does not create or verify mainnet escrow, sign on behalf of a user,
//! monitor the chain, or make a receipt spendable. State-directory rollback
//! also requires an independent anti-rollback witness before production use.

use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

mod payer;
pub use payer::PayerStore;

const MAX_RECEIPTS: usize = 10_000;
const MAX_RECEIPT_BYTES: usize = 4 * 1024;
const MAX_IDENTITY_BYTES: usize = 2 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    funding: Funding,
    receiver: String,
    initial: SignedState,
}

pub struct RecipientStore {
    root: PathBuf,
    _lock: File,
    tracker: RecipientTracker,
    by_payment_id: BTreeMap<Hash, PaymentReceipt>,
    count: usize,
    poisoned: bool,
}

fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| e.to_string())
}

fn plain_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = io(fs::symlink_metadata(path))?;
        require(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe wallet directory",
        )?;
    }
    Ok(())
}

fn bounded_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= max as u64,
        "unsafe or oversized wallet file",
    )?;
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes))?;
    require(bytes.len() <= max, "wallet file grew beyond bound")?;
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or("missing wallet directory")?;
    let temp = path.with_extension("pending");
    if temp.exists() {
        require(
            !io(fs::symlink_metadata(&temp))?.file_type().is_symlink(),
            "unsafe pending wallet file",
        )?;
        io(fs::remove_file(&temp))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(&temp))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())?;
    io(fs::rename(&temp, path))?;
    io(io(File::open(dir))?.sync_all())
}

fn receipt_name(sequence: u64) -> String {
    format!("{sequence:020}.json")
}

impl RecipientStore {
    pub fn open(
        root: &Path,
        funding: Funding,
        receiver: String,
        initial: SignedState,
    ) -> Result<Self> {
        plain_directory(root)?;
        io(fs::create_dir_all(root))?;
        if let Some(parent) = root.parent().filter(|p| !p.as_os_str().is_empty()) {
            io(io(File::open(parent))?.sync_all())?;
        }
        let lock_path = root.join(".wallet.lock");
        if lock_path.exists() {
            require(
                !io(fs::symlink_metadata(&lock_path))?
                    .file_type()
                    .is_symlink(),
                "unsafe wallet lock",
            )?;
        }
        let lock = io(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path))?;
        lock.try_lock()
            .map_err(|e| format!("wallet directory already owned: {e}"))?;

        let mut tracker =
            RecipientTracker::new(funding.clone(), receiver.clone(), initial.clone())?;
        let identity = Identity {
            funding,
            receiver,
            initial,
        };
        let identity_path = root.join("channel.json");
        let receipt_dir = root.join("receipts");
        plain_directory(&receipt_dir)?;
        io(fs::create_dir_all(&receipt_dir))?;
        io(io(File::open(root))?.sync_all())?;
        if identity_path.exists() {
            let bytes = bounded_file(&identity_path, MAX_IDENTITY_BYTES)?;
            let stored: Identity = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                stored == identity,
                "wallet belongs to another channel or receiver",
            )?;
            require(
                bytes == serde_json::to_vec(&stored).map_err(|e| e.to_string())?,
                "noncanonical wallet identity",
            )?;
        } else {
            for item in io(fs::read_dir(&receipt_dir))? {
                let item = io(item)?;
                let name = item.file_name();
                let name = name.to_str().ok_or("non-UTF8 wallet filename")?;
                require(
                    name.ends_with(".pending") && !io(item.file_type())?.is_symlink(),
                    "receipts exist without channel identity",
                )?;
            }
            let bytes = serde_json::to_vec(&identity).map_err(|e| e.to_string())?;
            require(
                bytes.len() <= MAX_IDENTITY_BYTES,
                "wallet identity too large",
            )?;
            atomic_write(&identity_path, &bytes)?;
        }

        let mut paths = Vec::new();
        let mut by_payment_id = BTreeMap::new();
        for item in io(fs::read_dir(&receipt_dir))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 wallet filename")?;
            if name.ends_with(".pending") {
                continue;
            }
            require(
                name.len() == 25
                    && name.ends_with(".json")
                    && name.as_bytes()[..20].iter().all(u8::is_ascii_digit),
                "unexpected wallet file",
            )?;
            paths.push(item.path());
            require(
                paths.len() <= MAX_RECEIPTS,
                "wallet receipt capacity reached",
            )?;
        }
        paths.sort();
        for (index, path) in paths.iter().enumerate() {
            let expected_sequence = u64::try_from(index + 1).map_err(|e| e.to_string())?;
            require(
                path.file_name().and_then(|n| n.to_str())
                    == Some(receipt_name(expected_sequence).as_str()),
                "wallet receipt sequence gap",
            )?;
            let bytes = bounded_file(path, MAX_RECEIPT_BYTES)?;
            let receipt: PaymentReceipt =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                bytes == serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
                "noncanonical wallet receipt",
            )?;
            tracker.apply_receipt(receipt.clone())?;
            require(
                by_payment_id.insert(receipt.payment_id, receipt).is_none(),
                "duplicate payment ID in wallet journal",
            )?;
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            tracker,
            by_payment_id,
            count: paths.len(),
            poisoned: false,
        })
    }

    pub fn latest(&self) -> &SignedState {
        self.tracker.latest()
    }

    /// Validate first, fsync the receipt and directory, then update in-memory
    /// state. After any I/O error the store stops until it is reopened/replayed.
    pub fn apply_receipt(&mut self, receipt: PaymentReceipt) -> Result<()> {
        require(!self.poisoned, "wallet stopped after storage failure")?;
        require(self.count < MAX_RECEIPTS, "wallet receipt capacity reached")?;
        let mut next = self.tracker.clone();
        next.apply_receipt(receipt.clone())?;
        let bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_RECEIPT_BYTES, "wallet receipt too large")?;
        let sequence = receipt.updated.state.sequence;
        let path = self.root.join("receipts").join(receipt_name(sequence));
        require(!path.exists(), "wallet receipt already exists")?;
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.tracker = next;
        self.by_payment_id.insert(receipt.payment_id, receipt);
        self.count += 1;
        Ok(())
    }

    /// After an interrupted reply, the payer can retry the identical offer.
    /// A different offer at the same invoice ID fails closed. The persisted
    /// receipt is returned only after its file has been durably published.
    pub fn accept_offer(
        &mut self,
        offer: PaymentOffer,
        receiver_secret: &str,
    ) -> Result<PaymentReceipt> {
        require(!self.poisoned, "wallet stopped after storage failure")?;
        offer.verify(&self.tracker.funding)?;
        if let Some(existing) = self.by_payment_id.get(&offer.payment_id) {
            require(
                existing.previous == offer.previous
                    && existing.updated.state == offer.proposed
                    && existing.sender == offer.sender
                    && existing.amount == offer.amount
                    && (if offer.sender == self.tracker.funding.party_a {
                        &existing.updated.signature_a
                    } else {
                        &existing.updated.signature_b
                    }) == &offer.sender_signature,
                "conflicting retry for payment ID",
            )?;
            return Ok(existing.clone());
        }
        require(
            offer.previous == *self.tracker.latest(),
            "offer does not extend latest local state",
        )?;
        let receipt = offer.cosign(&self.tracker.funding, receiver_secret)?;
        receipt.verify(&self.tracker.funding, &self.tracker.receiver)?;
        self.apply_receipt(receipt.clone())?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
