//! Optional process-local replay reuse, never a serialized ledger initializer.
//! Every retained prefix byte is compared again before its executed state is used.
use super::{ensure, Store};
use crate::kernel::{Hash, Ledger, Result};

const BLOCK_BYTES: usize = 4 * 1024 * 1024;
const COINS: usize = 4096;
pub(super) struct Witness {
    blocks: Vec<(Hash, Vec<u8>)>,
    ledger: Ledger,
}
#[derive(Default)]
struct Retention {
    blocks: Option<Vec<(Hash, Vec<u8>)>>,
    bytes: usize,
}
impl Retention {
    fn new() -> Self {
        Self {
            blocks: Some(Vec::new()),
            bytes: 0,
        }
    }
    fn push(&mut self, id: Hash, raw: Vec<u8>) {
        self.bytes = self.bytes.saturating_add(raw.len());
        if self.bytes > BLOCK_BYTES {
            self.blocks = None;
        }
        if let Some(blocks) = &mut self.blocks {
            blocks.push((id, raw));
        }
    }
    fn finish(self, ledger: &Ledger) -> Option<Witness> {
        self.blocks
            .filter(|_| ledger.coins().len() <= COINS)
            .map(|blocks| Witness {
                blocks,
                ledger: ledger.clone(),
            })
    }
}
impl Store {
    pub(crate) fn replay(&self, tip: Hash) -> Result<Ledger> {
        ensure(self.storage_ready(), "RESOURCE_WAIT poisoned storage")?;
        // This witness belongs to one Store with immutable genesis and Limits.
        // It can only be installed below, after complete native execution.
        let witness = self.replay_witness.borrow();
        let pin = self.ledger.chain_id();
        let mut path = Vec::new();
        let mut id = tip;
        let mut expected = None;
        while id != pin {
            let raw = self.get_block(id).inspect_err(|_| {
                if witness
                    .as_ref()
                    .is_some_and(|w| w.blocks.iter().any(|b| b.0 == id))
                {
                    self.poisoned.set(true);
                }
            })?;
            let h = u128::from_be_bytes(raw[68..84].try_into().unwrap());
            ensure(
                h > 0 && expected.is_none_or(|n| n == h),
                "INVALID ancestry height/cycle",
            )?;
            expected = Some(h - 1);
            path.push(id);
            id = raw[36..68].try_into().unwrap();
            ensure(
                path.len() as u64 <= self.limits.database_bytes / 270,
                "RESOURCE_WAIT replay index",
            )?;
        }
        path.reverse();
        let prefix = witness.as_ref().filter(|w| {
            w.blocks.len() <= path.len() && w.blocks.iter().zip(&path).all(|(b, id)| b.0 == *id)
        });
        // Verify all retained prefix bytes before cloning its state. A missing
        // known object poisons storage, rather than becoming an ordinary peer wait.
        if let Some(w) = prefix {
            for (id, exact) in &w.blocks {
                if self.get_retained_block(*id)? != *exact {
                    return Err(self.storage_fault("INVALID stored replay prefix"));
                }
            }
        }
        let mut ledger = if let Some(w) = prefix {
            w.ledger.clone()
        } else {
            Ledger::from_genesis(&self.genesis, pin, self.limits.coins)?
        };
        let skip = prefix.map_or(0, |w| w.blocks.len());
        let mut retained = Retention::new();
        for (n, id) in path.into_iter().enumerate() {
            let raw = self.get_retained_block(id)?;
            if n < skip {
                if raw != prefix.unwrap().blocks[n].1 {
                    return Err(self.storage_fault("INVALID stored replay prefix"));
                }
            } else {
                ledger.execute(&raw)?;
            }
            retained.push(id, raw);
        }
        drop(witness);
        // Resource exhaustion only discards optional reuse. The valid ledger
        // still returns, with no history/depth limit or altered selection rule.
        *self.replay_witness.borrow_mut() = retained.finish(&ledger);
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{block_id, genesis_id};
    use crate::store::Limits;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture(coins: usize) -> (Store, Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let v: Value = serde_json::from_str(include_str!(
            "../../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        let path = std::env::temp_dir().join(format!(
            "rld-survivor-replay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let s = Store::open(
            &path,
            &g,
            genesis_id(&g),
            Limits {
                coins,
                ..Limits::default()
            },
        )
        .unwrap();
        let mut branches = ["main_branch", "alternative_branch"].map(|name| {
            v[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| hex::decode(b["block_hex"].as_str().unwrap()).unwrap())
                .collect::<Vec<_>>()
        });
        branches[1] = [branches[0][..100].to_vec(), branches[1].clone()].concat();
        // SQL rows are deliberately unauthenticated inputs, never cached state.
        for raw in branches.iter().flatten() {
            s.db.execute(
                "INSERT OR IGNORE INTO blocks VALUES(?1,?2)",
                rusqlite::params![block_id(raw).unwrap().as_slice(), raw],
            )
            .unwrap();
        }
        let [main, alternate] = branches;
        (s, main, alternate)
    }
    fn uncached(s: &Store, blocks: &[Vec<u8>]) -> Ledger {
        let mut l = Ledger::from_genesis(&s.genesis, s.ledger.chain_id(), s.limits.coins).unwrap();
        for raw in blocks {
            l.execute(raw).unwrap();
        }
        l
    }
    #[test]
    fn native_prefix_extension_branch_miss_and_cold_start_agree() {
        let (s, main, alternate) = fixture(1_000_000);
        for blocks in [&main[..64], &main[..100], &main[..], &alternate[..]] {
            let expected = uncached(&s, blocks);
            let actual = s.replay(expected.tip().id()).unwrap();
            assert_eq!(actual.tip(), expected.tip());
            assert_eq!(actual.coins(), expected.coins());
            assert_eq!(actual.issued(), expected.issued());
        }
        let path = s.root.clone();
        let g = s.genesis.clone();
        let pin = s.ledger.chain_id();
        drop(s);
        let cold = Store::open(&path, &g, pin, Limits::default()).unwrap();
        assert!(cold.replay_witness.borrow().is_none());
        let expected = uncached(&cold, &alternate);
        let actual = cold.replay(expected.tip().id()).unwrap();
        assert_eq!(actual.tip(), expected.tip());
        assert_eq!(actual.coins(), expected.coins());
    }
    #[test]
    fn prefix_missing_or_changed_never_uses_retained_state() {
        for remove in [false, true] {
            let (s, main, _) = fixture(1_000_000);
            let parent = block_id(&main[99]).unwrap();
            s.replay(parent).unwrap();
            let id = block_id(&main[31]).unwrap();
            if remove {
                s.db.execute("DELETE FROM blocks WHERE id=?1", [id.as_slice()])
                    .unwrap();
            } else {
                let mut bad = main[31].clone();
                bad[100] ^= 1;
                s.db.execute(
                    "UPDATE blocks SET raw=?1 WHERE id=?2",
                    rusqlite::params![bad, id.as_slice()],
                )
                .unwrap();
            }
            assert!(s.replay(block_id(&main[100]).unwrap()).is_err());
            assert!(!s.storage_ready());
        }
    }
    #[test]
    fn invalid_suffix_and_different_resource_binding_cannot_seed_witness() {
        let (s, main, _) = fixture(1_000_000);
        let parent = block_id(&main[99]).unwrap();
        let expected = s.replay(parent).unwrap();
        let mut bad = main[100].clone();
        bad[220] ^= 1; // Wrong state root, with a genuinely valid nonce.
        let id = (0u128..1_000_000)
            .find_map(|nonce| {
                bad[252..268].copy_from_slice(&nonce.to_be_bytes());
                let id = block_id(&bad).unwrap();
                (id.as_slice() <= &bad[124..156]).then_some(id)
            })
            .expect("finite fixture nonce budget");
        s.db.execute(
            "INSERT INTO blocks VALUES(?1,?2)",
            rusqlite::params![id.as_slice(), bad],
        )
        .unwrap();
        assert_eq!(s.replay(id).err().unwrap(), "INVALID state root");
        assert_eq!(
            s.replay_witness.borrow().as_ref().unwrap().ledger.tip(),
            expected.tip()
        );
        assert!(s.storage_ready());
        let actual = s.replay(block_id(&main[100]).unwrap()).unwrap();
        assert_eq!(actual.tip(), uncached(&s, &main[..101]).tip());
        let (limited, main, _) = fixture(1);
        assert!(limited.replay(block_id(&main[99]).unwrap()).is_err());
        assert!(limited.replay_witness.borrow().is_none());
    }
    #[test]
    fn byte_capacity_discards_all_reuse_and_never_resumes_with_a_suffix() {
        let mut retained = Retention::new();
        retained.push([1; 32], vec![0; BLOCK_BYTES]);
        assert!(retained.blocks.is_some());
        retained.push([2; 32], vec![1]);
        assert!(retained.blocks.is_none());
        retained.push([3; 32], vec![2; 270]);
        assert!(retained.blocks.is_none());
        // Losing optional retention still leaves full genesis replay available.
        let (s, main, _) = fixture(1_000_000);
        let expected = uncached(&s, &main);
        assert!(retained.finish(&expected).is_none());
        let actual = s.replay(expected.tip().id()).unwrap();
        assert_eq!(actual.tip(), expected.tip());
        assert_eq!(actual.coins(), expected.coins());
    }
}
