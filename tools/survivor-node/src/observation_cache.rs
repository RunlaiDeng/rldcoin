//! Bounded process-local observations derived only from native executed changes.
//! Never serialized, never a ledger initializer, signing rule or finality proof.
use crate::kernel::{Hash, Tx};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) type Anchor = (Hash, u128);
pub(crate) const WITNESSES: usize = 256;
pub(crate) const DELTA_BYTES: usize = 1024 * 1024;
#[derive(Clone)]
pub(crate) struct Witness {
    pub unsigned: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,
    pub inclusion: Option<(Hash, u128)>,
    pub spends: BTreeMap<Vec<u8>, Hash>,
    pub ever_included: bool,
    pub location: Option<Hash>,
}
pub(crate) struct Block {
    pub id: Hash,
    pub height: u128,
    pub transactions: Vec<(Vec<u8>, Tx)>,
}
pub(crate) struct Delta {
    pub before: Anchor,
    pub after: Anchor,
    pub detached: Vec<Block>,
    pub attached: Vec<Block>,
}
pub(crate) struct Cache {
    anchor: Anchor,
    entries: BTreeMap<Hash, Witness>,
    order: VecDeque<Hash>,
    watchers: BTreeMap<Vec<u8>, BTreeSet<Hash>>,
}
impl Cache {
    pub fn new(anchor: Anchor) -> Self {
        Self {
            anchor,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            watchers: BTreeMap::new(),
        }
    }
    pub fn clear(&mut self, anchor: Anchor) {
        *self = Self::new(anchor);
    }
    fn bind(&mut self, anchor: Anchor) {
        if self.anchor != anchor {
            self.clear(anchor);
        }
    }
    fn touch(&mut self, id: Hash) {
        self.order.retain(|x| *x != id);
        self.order.push_back(id);
    }
    pub fn get(&mut self, anchor: Anchor, id: Hash, unsigned: &[u8]) -> Option<Witness> {
        self.bind(anchor);
        let witness = self.entries.get(&id)?;
        if witness.unsigned != unsigned {
            self.clear(anchor);
            return None;
        }
        let result = witness.clone();
        self.touch(id);
        Some(result)
    }
    pub fn location(&mut self, anchor: Anchor, id: Hash) -> Option<(Hash, Vec<u8>)> {
        self.bind(anchor);
        let w = self.entries.get(&id)?;
        let result = (w.location?, w.unsigned.clone());
        self.touch(id);
        Some(result)
    }
    fn remove(&mut self, id: Hash) {
        if let Some(w) = self.entries.remove(&id) {
            for input in w.inputs {
                if let Some(watching) = self.watchers.get_mut(&input) {
                    watching.remove(&id);
                    if watching.is_empty() {
                        self.watchers.remove(&input);
                    }
                }
            }
        }
        self.order.retain(|x| *x != id);
    }
    pub fn insert(&mut self, anchor: Anchor, id: Hash, w: Witness) {
        self.bind(anchor);
        self.remove(id);
        while self.entries.len() >= WITNESSES {
            self.remove(*self.order.front().expect("bounded observation order"));
        }
        for input in &w.inputs {
            self.watchers.entry(input.clone()).or_default().insert(id);
        }
        self.entries.insert(id, w);
        self.touch(id);
    }
    /// Called only after the exact native selection is durable. An absent or
    /// oversized delta discards the optional observations, never a ledger byte.
    pub fn committed(&mut self, after: Anchor, delta: Option<Delta>) {
        let Some(delta) = delta else {
            self.clear(after);
            return;
        };
        if delta.after != after {
            self.clear(after);
            return;
        }
        self.bind(delta.before);
        for block in delta.detached {
            for (_, tx) in block.transactions {
                for input in tx.inputs {
                    if let Some(ids) = self.watchers.get(&input) {
                        for id in ids {
                            if let Some(w) = self.entries.get_mut(id) {
                                if w.spends.get(&input) == Some(&block.id) {
                                    w.spends.remove(&input);
                                }
                            }
                        }
                    }
                }
                if let Some(w) = self.entries.get_mut(&tx.id) {
                    if w.inclusion == Some((block.id, block.height)) {
                        w.inclusion = None;
                    }
                }
            }
        }
        for block in delta.attached {
            for (raw, tx) in block.transactions {
                for input in &tx.inputs {
                    if let Some(ids) = self.watchers.get(input) {
                        for id in ids {
                            if let Some(w) = self.entries.get_mut(id) {
                                w.spends.insert(input.clone(), block.id);
                            }
                        }
                    }
                }
                // Native execution proved this transaction's exact selected
                // inclusion and its input consumption. Seed recent observations
                // without a second complete-history walk on the first query.
                let spends = tx.inputs.iter().map(|i| (i.clone(), block.id)).collect();
                self.insert(
                    delta.before,
                    tx.id,
                    Witness {
                        unsigned: raw[..raw.len() - 64].to_vec(),
                        inputs: tx.inputs,
                        inclusion: Some((block.id, block.height)),
                        spends,
                        ever_included: true,
                        location: Some(block.id),
                    },
                );
            }
        }
        self.anchor = after;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kernel::{genesis_id, Ledger},
        store::{Limits, Store},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    const NOW: u64 = 2_000_000_000;
    fn fixture(height: usize) -> (Store, Value, PathBuf) {
        let v: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let genesis = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-observation-cache-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut store =
            Store::open(&root, &genesis, genesis_id(&genesis), Limits::default()).unwrap();
        let blocks: Vec<_> = v["main_branch"].as_array().unwrap()[..height]
            .iter()
            .map(|v| hex::decode(v["block_hex"].as_str().unwrap()).unwrap())
            .collect();
        for (i, group) in blocks.chunks(32).enumerate() {
            store.accept_history([i as u8 + 1; 32], group, NOW).unwrap();
        }
        (store, v, root)
    }
    fn tx(v: &Value, name: &str) -> Vec<u8> {
        hex::decode(v[name]["transaction_hex"].as_str().unwrap()).unwrap()
    }
    fn compare(store: &Store, raw: &[u8]) -> Value {
        let tip = store.ledger().tip().clone();
        let revision = store.revision();
        let retained = store.transfer_observation(raw).unwrap();
        store
            .observation_cache
            .borrow_mut()
            .clear((tip.id(), revision));
        let complete = store.transfer_observation(raw).unwrap();
        assert_eq!(retained, complete);
        assert_eq!(store.ledger().tip(), &tip);
        assert_eq!(store.revision(), revision);
        retained
    }
    #[test]
    fn executed_extension_reorg_cold_start_and_stale_anchor_agree_with_full_scan() {
        let (mut store, v, root) = fixture(102);
        let payment = tx(&v, "payment");
        let onward = tx(&v, "onward");
        assert!(!store.observation_cache.borrow().entries.is_empty());
        assert_eq!(compare(&store, &payment)["ledger"], "INCLUDED");
        for (i, b) in v["alternative_branch"].as_array().unwrap()[..3]
            .iter()
            .enumerate()
        {
            let raw = hex::decode(b["block_hex"].as_str().unwrap()).unwrap();
            store.accept([80 + i as u8; 32], &raw, NOW).unwrap();
            compare(&store, &payment);
            compare(&store, &onward);
        }
        assert_eq!(compare(&store, &payment)["ledger"], "DETACHED");
        let expected = compare(&store, &payment);
        store
            .observation_cache
            .borrow_mut()
            .clear(([238; 32], u128::MAX));
        assert_eq!(store.transfer_observation(&payment).unwrap(), expected);
        let genesis = store.genesis_bytes().to_vec();
        let pin = store.ledger().chain_id();
        drop(store);
        let store = Store::open(&root, &genesis, pin, Limits::default()).unwrap();
        assert_eq!(compare(&store, &payment), expected);
    }
    #[test]
    fn cached_inclusion_cannot_hide_corruption_or_loss_before_the_tip() {
        for missing in [false, true] {
            let (store, v, root) = fixture(102);
            let payment = tx(&v, "payment");
            let observation = store.transfer_observation(&payment).unwrap();
            let id: Hash = hex::decode(observation["inclusion"]["block_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_ne!(id, store.ledger().tip().id());
            let db = rusqlite::Connection::open(root.join("ledger.sqlite3")).unwrap();
            if missing {
                db.execute("DELETE FROM blocks WHERE id=?1", [id.as_slice()])
                    .unwrap();
            } else {
                let mut raw = store.get_block(id).unwrap();
                *raw.last_mut().unwrap() ^= 1;
                db.execute(
                    "UPDATE blocks SET raw=?1 WHERE id=?2",
                    rusqlite::params![raw, id.as_slice()],
                )
                .unwrap();
            }
            drop(db);
            assert!(store.transfer_observation(&payment).is_err());
            assert!(!store.storage_ready());
            assert!(store
                .get_transaction(
                    crate::kernel::decode_tx(&payment, store.ledger().chain_id())
                        .unwrap()
                        .id
                )
                .is_err());
        }
    }
    #[test]
    fn invalid_group_cannot_publish_an_observation_before_value_commit() {
        let (mut store, v, _) = fixture(101);
        let payment = tx(&v, "payment");
        let onward = tx(&v, "onward");
        let before = store.transfer_observation(&payment).unwrap();
        let mut blocks: Vec<_> = v["main_branch"].as_array().unwrap()[101..103]
            .iter()
            .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
            .collect();
        *blocks[1].last_mut().unwrap() ^= 1;
        assert!(store.accept_history([90; 32], &blocks, NOW).is_err());
        assert_eq!(store.transfer_observation(&payment).unwrap(), before);
        let id = crate::kernel::decode_tx(&onward, store.ledger().chain_id())
            .unwrap()
            .id;
        assert!(store
            .get_transaction(id)
            .unwrap_err()
            .starts_with("MISSING_HISTORY"));
    }
    #[test]
    fn finite_eviction_preserves_old_history_and_cold_reconstruction() {
        let (mut store, _, root) = fixture(0);
        // Deliberately public NO-VALUE owner; never production signing material.
        let key = SigningKey::from_bytes(&[11; 32]);
        let owner = key.verifying_key().to_bytes();
        let mut candidate: Ledger = store.ledger().clone();
        let mut group = Vec::new();
        let mut first = None;
        for height in 1u128..=420 {
            let mut transactions = Vec::new();
            if height > 100 {
                let (input, coin) = candidate
                    .coins()
                    .iter()
                    .find(|(_, c)| c.maturity <= height && c.amount > 1)
                    .unwrap();
                let mut raw = 1u16.to_be_bytes().to_vec();
                raw.extend(candidate.chain_id());
                raw.extend(owner);
                raw.extend(1u16.to_be_bytes());
                raw.extend(input);
                raw.extend(1u16.to_be_bytes());
                raw.extend(owner);
                raw.extend((coin.amount - 1).to_be_bytes());
                raw.extend(1u128.to_be_bytes());
                raw.extend(u128::MAX.to_be_bytes());
                raw.extend(
                    key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), &raw].concat())
                        .to_bytes(),
                );
                if first.is_none() {
                    first = Some(raw.clone());
                }
                transactions.push(raw);
            }
            let mut job = candidate
                .mining_job(owner, transactions, candidate.tip().timestamp() + 600, NOW)
                .unwrap();
            let raw = job.attempt(1_000_000).unwrap();
            candidate.execute(&raw).unwrap();
            group.push(raw);
            if group.len() == 32 || height == 420 {
                let mut id = [0; 32];
                id[16..].copy_from_slice(&height.to_be_bytes());
                store.accept_history(id, &group, NOW).unwrap();
                group.clear();
            }
        }
        let first = first.unwrap();
        let id = crate::kernel::decode_tx(&first, store.ledger().chain_id())
            .unwrap()
            .id;
        {
            let cache = store.observation_cache.borrow();
            assert_eq!(cache.entries.len(), WITNESSES);
            assert!(!cache.entries.contains_key(&id));
            assert!(cache.watchers.len() <= WITNESSES * 32);
            assert!(cache
                .watchers
                .values()
                .all(|ids| ids.iter().all(|id| cache.entries.contains_key(id))));
        }
        assert_eq!(store.get_transaction(id).unwrap(), first);
        let expected = compare(&store, &first);
        assert_eq!(expected["ledger"], "INCLUDED");
        let genesis = store.genesis_bytes().to_vec();
        let pin = store.ledger().chain_id();
        drop(store);
        let store = Store::open(&root, &genesis, pin, Limits::default()).unwrap();
        assert_eq!(compare(&store, &first), expected);
    }
}
