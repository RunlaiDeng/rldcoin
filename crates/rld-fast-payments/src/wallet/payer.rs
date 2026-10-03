//! Sender-side candidate journal. It retains one pending signed offer across
//! outages so a payer never silently creates two offers for one channel state.

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PayerIdentity {
    funding: Funding,
    payer: String,
    initial: SignedState,
}

pub struct PayerStore {
    root: PathBuf,
    _lock: File,
    funding: Funding,
    payer: String,
    latest: SignedState,
    pending: Option<PaymentOffer>,
    committed: BTreeMap<Hash, PaymentReceipt>,
    poisoned: bool,
}

impl PayerStore {
    pub fn open(
        root: &Path,
        funding: Funding,
        payer: String,
        initial: SignedState,
    ) -> Result<Self> {
        require(
            payer == funding.party_a || payer == funding.party_b,
            "payer is not a channel party",
        )?;
        initial.verify(&funding)?;
        require(
            initial.state.sequence == 0,
            "payer must start from opening state",
        )?;
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
        let receipt_dir = root.join("receipts");
        plain_directory(&receipt_dir)?;
        io(fs::create_dir_all(&receipt_dir))?;
        io(io(File::open(root))?.sync_all())?;

        let identity = PayerIdentity {
            funding: funding.clone(),
            payer: payer.clone(),
            initial: initial.clone(),
        };
        let identity_path = root.join("channel.json");
        if identity_path.exists() {
            let bytes = bounded_file(&identity_path, MAX_IDENTITY_BYTES)?;
            let stored: PayerIdentity =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                stored == identity,
                "payer wallet belongs to another channel",
            )?;
            require(
                bytes == serde_json::to_vec(&stored).map_err(|e| e.to_string())?,
                "noncanonical payer wallet identity",
            )?;
        } else {
            for item in io(fs::read_dir(&receipt_dir))? {
                let item = io(item)?;
                let name = item.file_name();
                let name = name.to_str().ok_or("non-UTF8 payer receipt filename")?;
                require(
                    name.ends_with(".pending") && !io(item.file_type())?.is_symlink(),
                    "payer records exist without channel identity",
                )?;
            }
            require(
                !root.join("offer.json").exists(),
                "payer offer without channel identity",
            )?;
            let bytes = serde_json::to_vec(&identity).map_err(|e| e.to_string())?;
            require(
                bytes.len() <= MAX_IDENTITY_BYTES,
                "payer identity too large",
            )?;
            atomic_write(&identity_path, &bytes)?;
        }

        let mut paths = Vec::new();
        for item in io(fs::read_dir(&receipt_dir))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 payer receipt filename")?;
            if name.ends_with(".pending") {
                require(
                    !io(item.file_type())?.is_symlink(),
                    "unsafe pending receipt",
                )?;
                continue;
            }
            require(
                name.len() == 25
                    && name.ends_with(".json")
                    && name.as_bytes()[..20].iter().all(u8::is_ascii_digit),
                "unexpected payer receipt file",
            )?;
            paths.push(item.path());
            require(
                paths.len() <= MAX_RECEIPTS,
                "payer receipt capacity reached",
            )?;
        }
        paths.sort();
        let mut latest = initial;
        let mut committed = BTreeMap::new();
        for (index, path) in paths.iter().enumerate() {
            let sequence = u64::try_from(index + 1).map_err(|e| e.to_string())?;
            require(
                path.file_name().and_then(|n| n.to_str()) == Some(receipt_name(sequence).as_str()),
                "payer receipt sequence gap",
            )?;
            let bytes = bounded_file(path, MAX_RECEIPT_BYTES)?;
            let receipt: PaymentReceipt =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                bytes == serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
                "noncanonical payer receipt",
            )?;
            require(
                receipt.previous == latest && receipt.sender == payer,
                "payer receipt does not extend latest state",
            )?;
            let receiver = if payer == funding.party_a {
                &funding.party_b
            } else {
                &funding.party_a
            };
            receipt.verify(&funding, receiver)?;
            latest = receipt.updated.clone();
            require(
                committed.insert(receipt.payment_id, receipt).is_none(),
                "duplicate payer payment ID",
            )?;
        }

        let offer_path = root.join("offer.json");
        let pending = if offer_path.exists() {
            let bytes = bounded_file(&offer_path, MAX_RECEIPT_BYTES)?;
            let offer: PaymentOffer = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            require(
                bytes == serde_json::to_vec(&offer).map_err(|e| e.to_string())?,
                "noncanonical pending payer offer",
            )?;
            offer.verify(&funding)?;
            require(
                offer.sender == payer,
                "pending offer belongs to another payer",
            )?;
            if let Some(receipt) = committed.get(&offer.payment_id) {
                require(
                    receipt.previous == offer.previous
                        && receipt.updated.state == offer.proposed
                        && receipt.amount == offer.amount
                        && (if payer == funding.party_a {
                            &receipt.updated.signature_a
                        } else {
                            &receipt.updated.signature_b
                        }) == &offer.sender_signature,
                    "pending offer conflicts with committed receipt",
                )?;
                io(fs::remove_file(&offer_path))?;
                io(io(File::open(root))?.sync_all())?;
                None
            } else {
                require(offer.previous == latest, "pending offer is stale")?;
                Some(offer)
            }
        } else {
            None
        };
        Ok(Self {
            root: root.into(),
            _lock: lock,
            funding,
            payer,
            latest,
            pending,
            committed,
            poisoned: false,
        })
    }

    pub fn latest(&self) -> &SignedState {
        &self.latest
    }

    pub fn pending(&self) -> Option<&PaymentOffer> {
        self.pending.as_ref()
    }

    pub fn begin_payment(
        &mut self,
        secret: &str,
        amount: Amount,
        payment_id: Hash,
    ) -> Result<PaymentOffer> {
        require(!self.poisoned, "payer wallet stopped after storage failure")?;
        if let Some(offer) = &self.pending {
            require(
                offer.payment_id == payment_id && offer.amount == amount,
                "payer has a pending payment",
            )?;
            return Ok(offer.clone());
        }
        require(
            !self.committed.contains_key(&payment_id),
            "payment ID already committed",
        )?;
        require(
            self.committed.len() < MAX_RECEIPTS,
            "payer receipt capacity reached",
        )?;
        let offer = PaymentOffer::new(
            &self.funding,
            self.latest.clone(),
            self.payer.clone(),
            secret,
            amount,
            payment_id,
        )?;
        let bytes = serde_json::to_vec(&offer).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_RECEIPT_BYTES, "payer offer too large")?;
        let path = self.root.join("offer.json");
        require(!path.exists(), "unexpected payer pending offer")?;
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.pending = Some(offer.clone());
        Ok(offer)
    }

    pub fn complete_payment(&mut self, receipt: PaymentReceipt) -> Result<bool> {
        require(!self.poisoned, "payer wallet stopped after storage failure")?;
        if let Some(existing) = self.committed.get(&receipt.payment_id) {
            require(existing == &receipt, "conflicting completed receipt")?;
            return Ok(false);
        }
        let offer = self.pending.as_ref().ok_or("no pending payer offer")?;
        require(
            receipt.previous == offer.previous
                && receipt.updated.state == offer.proposed
                && receipt.amount == offer.amount
                && receipt.payment_id == offer.payment_id
                && receipt.sender == self.payer
                && (if self.payer == self.funding.party_a {
                    &receipt.updated.signature_a
                } else {
                    &receipt.updated.signature_b
                }) == &offer.sender_signature,
            "receipt does not complete pending payer offer",
        )?;
        let receiver = if self.payer == self.funding.party_a {
            &self.funding.party_b
        } else {
            &self.funding.party_a
        };
        receipt.verify(&self.funding, receiver)?;
        let bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_RECEIPT_BYTES, "payer receipt too large")?;
        let path = self
            .root
            .join("receipts")
            .join(receipt_name(receipt.updated.state.sequence));
        require(!path.exists(), "payer receipt already exists")?;
        if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        self.latest = receipt.updated.clone();
        self.committed.insert(receipt.payment_id, receipt);
        self.pending = None;
        let offer_path = self.root.join("offer.json");
        if let Err(error) = (|| {
            io(fs::remove_file(&offer_path))?;
            io(io(File::open(&self.root))?.sync_all())
        })() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
