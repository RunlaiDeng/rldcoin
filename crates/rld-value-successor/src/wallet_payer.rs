//! Candidate payer journal with a durable, signed watchtower-delivery record.
//! Whole-directory rollback and adopted funding still need separate protection.

use crate::{chain::CandidateChain, watchtower::WatchedReceipt, Result};
use rld_core::{validate_ed25519_public_key, AdmissionHash32 as Hash, Amount};
use rld_fast_payments::{wallet::PayerStore, Funding, PaymentOffer, SignedState};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_DELIVERY_BYTES: usize = 32_768;
const MAX_DELIVERIES: usize = 10_000;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WatcherPin {
    public_key: String,
}

pub struct WatchedPayer {
    root: PathBuf,
    _lock: File,
    journal: PayerStore,
    funding: Funding,
    payer: String,
    watcher: String,
    committed: BTreeMap<Hash, WatchedReceipt>,
    poisoned: bool,
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

fn owner_directory(path: &Path) -> Result<()> {
    let metadata = io(fs::symlink_metadata(path))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("unsafe watched payer directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("watched payer directory must be owner-only".into());
        }
    }
    Ok(())
}

fn create_owner_directory(path: &Path) -> Result<()> {
    if path.exists() {
        return owner_directory(path);
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    io(builder.create(path))?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        io(io(File::open(parent))?.sync_all())?;
    }
    owner_directory(path)
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata = io(fs::symlink_metadata(path))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        return Err("unsafe or oversized watched payer file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("watched payer file must be owner-only".into());
        }
    }
    let mut bytes = Vec::new();
    io(io(File::open(path))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes))?;
    if bytes.len() > limit {
        return Err("watched payer file exceeded bound".into());
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing watched payer directory")?;
    let pending = path.with_extension("pending");
    if pending.exists() {
        let metadata = io(fs::symlink_metadata(&pending))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("unsafe pending watched payer file".into());
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
    io(io(File::open(parent))?.sync_all())
}

fn receipt_name(sequence: u64) -> String {
    format!("{sequence:020}.json")
}

impl WatchedPayer {
    pub fn open(
        root: &Path,
        funding: Funding,
        payer: String,
        initial: SignedState,
        watcher: String,
    ) -> Result<Self> {
        validate_ed25519_public_key(&watcher)?;
        create_owner_directory(root)?;
        let lock_path = root.join(".watched-payer.lock");
        if lock_path.exists()
            && io(fs::symlink_metadata(&lock_path))?
                .file_type()
                .is_symlink()
        {
            return Err("unsafe watched payer lock".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = io(options.open(lock_path))?;
        lock.try_lock()
            .map_err(|error| format!("watched payer directory already owned: {error}"))?;

        let pin_path = root.join("watcher.json");
        let pin = WatcherPin {
            public_key: watcher.clone(),
        };
        if pin_path.exists() {
            let bytes = bounded(&pin_path, 1024)?;
            let stored: WatcherPin =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if stored != pin || bytes != serde_json::to_vec(&stored).map_err(|e| e.to_string())? {
                return Err("watched payer watcher pin changed".into());
            }
        } else {
            if root.join("payer").exists() || root.join("deliveries").exists() {
                return Err("watched payer journal exists without watcher pin".into());
            }
            atomic_write(
                &pin_path,
                &serde_json::to_vec(&pin).map_err(|error| error.to_string())?,
            )?;
        }
        let delivery_dir = root.join("deliveries");
        create_owner_directory(&delivery_dir)?;
        create_owner_directory(&root.join("payer"))?;
        create_owner_directory(&root.join("payer").join("receipts"))?;
        let mut journal =
            PayerStore::open(&root.join("payer"), funding.clone(), payer.clone(), initial)?;
        let mut paths = Vec::new();
        for item in io(fs::read_dir(&delivery_dir))? {
            let item = io(item)?;
            let name = item.file_name();
            let name = name.to_str().ok_or("non-UTF8 watched payer filename")?;
            if name.ends_with(".pending") {
                if io(item.file_type())?.is_symlink() {
                    return Err("unsafe pending watched payer delivery".into());
                }
                continue;
            }
            if name.len() != 25
                || !name.ends_with(".json")
                || !name.as_bytes()[..20].iter().all(u8::is_ascii_digit)
            {
                return Err("unexpected watched payer delivery file".into());
            }
            paths.push(item.path());
            if paths.len() > MAX_DELIVERIES {
                return Err("watched payer delivery capacity reached".into());
            }
        }
        paths.sort();
        let committed_sequence = journal.latest().state.sequence;
        let mut committed = BTreeMap::new();
        for (index, path) in paths.iter().enumerate() {
            let sequence = u64::try_from(index + 1).map_err(|error| error.to_string())?;
            if path.file_name().and_then(|name| name.to_str())
                != Some(receipt_name(sequence).as_str())
            {
                return Err("watched payer delivery sequence gap".into());
            }
            let bytes = bounded(path, MAX_DELIVERY_BYTES)?;
            let delivery: WatchedReceipt =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if bytes != serde_json::to_vec(&delivery).map_err(|error| error.to_string())?
                || delivery.receipt.updated.state.sequence != sequence
            {
                return Err("noncanonical or misnumbered watched payer delivery".into());
            }
            delivery.verify(&funding, &payer, &watcher)?;
            if committed
                .insert(delivery.receipt.payment_id, delivery.clone())
                .is_some()
            {
                return Err("duplicate watched payer payment ID".into());
            }
            if sequence <= committed_sequence {
                let receipt_path = root
                    .join("payer")
                    .join("receipts")
                    .join(receipt_name(sequence));
                let receipt_bytes = bounded(&receipt_path, MAX_DELIVERY_BYTES)?;
                if receipt_bytes
                    != serde_json::to_vec(&delivery.receipt).map_err(|e| e.to_string())?
                {
                    return Err("payer receipt and watched delivery differ".into());
                }
            } else if sequence == committed_sequence + 1 {
                journal.complete_payment(delivery.receipt)?;
            } else {
                return Err("watched payer delivery moved beyond journal".into());
            }
        }
        if journal.latest().state.sequence != paths.len() as u64 {
            return Err("payer receipt lacks a watched delivery".into());
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            journal,
            funding,
            payer,
            watcher,
            committed,
            poisoned: false,
        })
    }

    pub fn latest(&self) -> &SignedState {
        self.journal.latest()
    }

    pub fn pending(&self) -> Option<&PaymentOffer> {
        self.journal.pending()
    }

    pub fn recorded(&self, payment_id: Hash) -> Option<&WatchedReceipt> {
        self.committed.get(&payment_id)
    }

    pub fn begin_payment(
        &mut self,
        secret: &str,
        amount: Amount,
        payment_id: Hash,
    ) -> Result<PaymentOffer> {
        if self.poisoned {
            return Err("watched payer stopped after storage failure".into());
        }
        self.journal.begin_payment(secret, amount, payment_id)
    }

    pub fn complete_payment(
        &mut self,
        chain: &CandidateChain,
        delivery: WatchedReceipt,
    ) -> Result<bool> {
        if self.poisoned {
            return Err("watched payer stopped after storage failure".into());
        }
        delivery.verify_on_chain(&self.funding, &self.payer, &self.watcher, chain)?;
        let offer = self
            .journal
            .pending()
            .ok_or("no pending watched payer offer")?;
        if delivery.receipt.previous != offer.previous
            || delivery.receipt.updated.state != offer.proposed
            || delivery.receipt.payment_id != offer.payment_id
            || delivery.receipt.amount != offer.amount
            || delivery.receipt.sender != offer.sender
            || (if offer.sender == self.funding.party_a {
                &delivery.receipt.updated.signature_a
            } else {
                &delivery.receipt.updated.signature_b
            }) != &offer.sender_signature
        {
            return Err("watched receipt does not complete the pending offer".into());
        }
        let sequence = delivery.receipt.updated.state.sequence;
        let bytes = serde_json::to_vec(&delivery).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_DELIVERY_BYTES {
            return Err("watched payer delivery too large".into());
        }
        let path = self.root.join("deliveries").join(receipt_name(sequence));
        if path.exists() {
            if bounded(&path, MAX_DELIVERY_BYTES)? != bytes {
                return Err("conflicting watched payer delivery".into());
            }
        } else if let Err(error) = atomic_write(&path, &bytes) {
            self.poisoned = true;
            return Err(error);
        }
        match self.journal.complete_payment(delivery.receipt.clone()) {
            Ok(changed) => {
                self.committed.insert(delivery.receipt.payment_id, delivery);
                Ok(changed)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signed_state_hash,
        watchtower::{WatchAck, WatchPackage, CANDIDATE_STATUS},
        ActionFee, ActionFeeIntent, DisputeAction,
    };
    use rld_core::{generate_identity, sign_bytes};
    use rld_fast_payments::{ChannelState, FundingOutpoint};
    use rld_pow::OutPoint;

    #[test]
    fn saved_delivery_recovers_pending_receipt_and_missing_evidence_fails_closed() {
        let a = generate_identity();
        let b = generate_identity();
        let watcher = generate_identity();
        let funding = Funding {
            chain_id: Hash([1; 32]),
            outpoint: FundingOutpoint {
                transaction: Hash([2; 32]),
                index: 0,
            },
            party_a: a.public_key.clone(),
            party_b: b.public_key.clone(),
            capacity: Amount(1_000),
            close_fee: Amount(1),
        };
        let initial_state = ChannelState::initial(&funding).unwrap();
        let bytes = initial_state.signing_bytes(&funding).unwrap();
        let initial = SignedState {
            state: initial_state,
            signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
            signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
        };
        let offer = PaymentOffer::new(
            &funding,
            initial.clone(),
            a.public_key.clone(),
            &a.secret_key,
            Amount(10),
            Hash([3; 32]),
        )
        .unwrap();
        let receipt = offer.cosign(&funding, &b.secret_key).unwrap();
        let intent = ActionFeeIntent {
            chain_id: funding.chain_id,
            action: DisputeAction::Challenge,
            channel: funding.id().unwrap(),
            signed_state: signed_state_hash(&receipt.updated).unwrap(),
            input: OutPoint {
                transaction: Hash([4; 32]),
                index: 0,
            },
            owner: b.public_key.clone(),
            fee: Amount(1),
            change: Amount(9),
            valid_through_height: 1_000,
        };
        let package = WatchPackage {
            funding: funding.clone(),
            state: receipt.updated.clone(),
            fee: ActionFee {
                owner_signature: sign_bytes(&b.secret_key, &intent.signing_bytes().unwrap())
                    .unwrap(),
                intent,
            },
        };
        let delivery = WatchedReceipt {
            status: CANDIDATE_STATUS.into(),
            live_rld: false,
            receipt: receipt.clone(),
            watch_ack: WatchAck::sign_saved(&package, &watcher.public_key, &watcher.secret_key)
                .unwrap(),
            watch_package: package,
        };
        let root = std::env::temp_dir().join(format!("rld-watched-payer-{}", watcher.public_key));
        let mut payer = WatchedPayer::open(
            &root,
            funding.clone(),
            a.public_key.clone(),
            initial.clone(),
            watcher.public_key.clone(),
        )
        .unwrap();
        assert_eq!(
            payer
                .begin_payment(&a.secret_key, Amount(10), Hash([3; 32]))
                .unwrap(),
            offer
        );
        atomic_write(
            &root.join("deliveries").join(receipt_name(1)),
            &serde_json::to_vec(&delivery).unwrap(),
        )
        .unwrap();
        drop(payer);
        let restored = WatchedPayer::open(
            &root,
            funding.clone(),
            a.public_key.clone(),
            initial.clone(),
            watcher.public_key.clone(),
        )
        .unwrap();
        assert_eq!(restored.latest(), &receipt.updated);
        assert!(restored.pending().is_none());
        assert_eq!(restored.recorded(receipt.payment_id), Some(&delivery));
        drop(restored);
        std::fs::remove_file(root.join("deliveries").join(receipt_name(1))).unwrap();
        assert!(
            WatchedPayer::open(&root, funding, a.public_key, initial, watcher.public_key).is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
