//! Proactive, bounded complete-history offers for explicitly admitted one-way
//! contacts. These cursors schedule retained bytes; they never initialize or
//! authenticate ledger state, and restart traverses the native history again.
use super::{ensure, err, peer_id, Hash, Network, Result, Store};
use rusqlite::params;
use std::collections::BTreeMap;

const OFFERS_PER_TICK: usize = 16;
type Hints = (BTreeMap<Hash, Hash>, Option<Hash>);

#[derive(Debug)]
pub(super) enum OfflineHistoryError {
    Contact(String),
    Native(String),
}

impl Network {
    fn offline_history_hints(&self) -> Result<Hints> {
        let mut statement = self
            .carriage
            .db
            .prepare("SELECT peer,last_block FROM offline_history")
            .map_err(err)?;
        let mut rows = statement.query([]).map_err(err)?;
        let mut hints = BTreeMap::new();
        while let Some(row) = rows.next().map_err(err)? {
            ensure(hints.len() < 64, "INVALID_ENCODING offline history peers")?;
            let peer: Hash = row
                .get::<_, Vec<u8>>(0)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING offline history peer")?;
            let cursor: Hash = row
                .get::<_, Vec<u8>>(1)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING offline history cursor")?;
            ensure(
                self.offline_peers.contains(&peer) && !hints.contains_key(&peer),
                "INVALID_CRYPTO offline history peer admission",
            )?;
            hints.insert(peer, cursor);
        }
        drop(rows);
        drop(statement);
        let mut statement = self
            .carriage
            .db
            .prepare("SELECT one,peer FROM offline_history_rotation")
            .map_err(err)?;
        let mut rows = statement.query([]).map_err(err)?;
        let mut rotation = None;
        while let Some(row) = rows.next().map_err(err)? {
            let one: i64 = row.get(0).map_err(err)?;
            let peer: Hash = row
                .get::<_, Vec<u8>>(1)
                .map_err(err)?
                .try_into()
                .map_err(|_| "INVALID_ENCODING offline history rotation")?;
            ensure(
                one == 1 && rotation.is_none() && self.offline_peers.contains(&peer),
                "INVALID_CRYPTO offline history rotation admission",
            )?;
            rotation = Some(peer);
        }
        Ok((hints, rotation))
    }

    pub(super) fn open_offline_history(&mut self) -> Result<()> {
        if self.offline_peers.is_empty() {
            return Ok(());
        }
        // Pure local scheduling metadata, bounded by the existing SQLite byte
        // ceiling and at most the 64 independently admitted offline identities.
        self.carriage.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS offline_history (peer BLOB PRIMARY KEY,last_block BLOB NOT NULL);\
             CREATE TABLE IF NOT EXISTS offline_history_rotation (one INTEGER PRIMARY KEY CHECK(one=1),peer BLOB NOT NULL);",
        ).map_err(err)?;
        let (hints, _) = self.offline_history_hints()?;
        // Even a well-typed saved cursor cannot establish what a destination
        // possesses. Replay offers from genesis on every ordinary cold startup.
        if !hints.is_empty() {
            let changed = self
                .carriage
                .db
                .execute(
                    "UPDATE offline_history SET last_block=?1",
                    [self.chain.as_slice()],
                )
                .map_err(err)?;
            ensure(
                changed == hints.len(),
                "RESOURCE_WAIT offline history restart cursor",
            )?;
        }
        self.carriage.capacity(0, 0)
    }

    fn offline_history_cursor(&self, peer: Hash, block: Hash, new: bool) -> Result<()> {
        if new {
            self.carriage.capacity(96, 0)?;
        }
        let changed = self.carriage.db.execute(
            "INSERT INTO offline_history(peer,last_block) VALUES(?1,?2) ON CONFLICT(peer) DO UPDATE SET last_block=excluded.last_block",
            params![peer.as_slice(), block.as_slice()],
        ).map_err(err)?;
        ensure(changed == 1, "RESOURCE_WAIT offline history cursor write")
    }

    pub(super) fn offer_offline_history(
        &mut self,
        store: &Store,
    ) -> std::result::Result<(), OfflineHistoryError> {
        use OfflineHistoryError::{Contact, Native};
        if self.offline_peers.is_empty() {
            return Ok(());
        }
        let (hints, rotation) = self.offline_history_hints().map_err(Contact)?;
        let mut peers = self.offline_peers.clone();
        peers.sort_unstable();
        let peer = peers
            .iter()
            .find(|peer| rotation.is_none_or(|last| **peer > last))
            .copied()
            .unwrap_or(peers[0]);
        if rotation.is_none() {
            self.carriage.capacity(64, 0).map_err(Contact)?;
        }
        // Rotate even if this peer's queue is full. A single unavailable
        // destination cannot pin every other explicitly admitted destination.
        let changed = self.carriage.db.execute(
            "INSERT INTO offline_history_rotation(one,peer) VALUES(1,?1) ON CONFLICT(one) DO UPDATE SET peer=excluded.peer",
            [peer.as_slice()],
        ).map_err(err).map_err(Contact)?;
        ensure(changed == 1, "RESOURCE_WAIT offline history peer rotation").map_err(Contact)?;
        let cursor = hints.get(&peer).copied().unwrap_or(self.chain);
        if cursor == store.ledger().tip().id() {
            // This skips only scheduling work. It grants no receipt, inclusion,
            // native state or remote-possession authority and resets on restart.
            return Ok(());
        }
        // This is intentionally the existing complete native-derived ancestry
        // walk. There is no cached ledger or unchecked peer prefix initializer.
        let selected = store.selected_ids().map_err(Native)?;
        let start = if let Some(position) = selected.iter().position(|id| *id == cursor) {
            position + 1
        } else {
            // A genuine former branch is retained natively. An arbitrary missing
            // or corrupt cursor target refuses rather than silently skipping it.
            store.get_block(cursor).map_err(Native)?;
            self.offline_history_cursor(peer, self.chain, !hints.contains_key(&peer))
                .map_err(Contact)?;
            1
        };
        let mut new = !hints.contains_key(&peer);
        for id in selected.into_iter().skip(start).take(OFFERS_PER_TICK) {
            let raw = store.get_retained_block(id).map_err(Native)?;
            let packet = self
                .carriage
                .originate_unique(&self.key, peer_id(peer), 3, &raw)
                .map_err(Contact)?;
            let durable = self
                .carriage
                .packet(packet.id())
                .map_err(Contact)?
                .ok_or_else(|| Contact("MISSING_HISTORY offline offered packet".into()))?;
            ensure(
                durable.raw() == packet.raw()
                    && durable.payload() == raw
                    && durable.kind() == 3
                    && durable.destination() == peer_id(peer),
                "INVALID_CRYPTO offline offered packet binding",
            )
            .map_err(Contact)?;
            // A failure here leaves the complete packet durable. Exact retry
            // coalesces it before advancing; an unoffered parent is never skipped.
            self.offline_history_cursor(peer, id, new)
                .map_err(Contact)?;
            new = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Published deterministic NO-VALUE fixture seeds, never operator custody.
    use super::*;
    use crate::{
        carriage::Budget,
        kernel::{genesis_id, Ledger},
        store::Limits,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::{json, Value};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const START: u64 = 1_000_000;
    const NOW: u64 = 2_000_000_000;

    fn branch(genesis: &[u8], miner: u8, count: u8) -> Vec<Vec<u8>> {
        let mut ledger = Ledger::from_genesis(genesis, genesis_id(genesis), 1_000_000).unwrap();
        let key = SigningKey::from_bytes(&[miner; 32]);
        let mut blocks = Vec::new();
        for height in 1..=count {
            let mut job = ledger
                .mining_job(
                    key.verifying_key().to_bytes(),
                    vec![],
                    START + u64::from(height) * 600,
                    NOW,
                )
                .unwrap();
            let raw = job.attempt(1_000_000).unwrap();
            ledger.execute(&raw).unwrap();
            blocks.push(raw);
        }
        blocks
    }

    fn fixture(count: u8, packets: usize) -> (PathBuf, Vec<u8>, Store, Network, Hash) {
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-offline-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let mut genesis =
            hex::decode(vectors["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        getrandom::getrandom(&mut genesis[13..45]).unwrap();
        genesis[45..53].copy_from_slice(&START.to_be_bytes());
        let chain = genesis_id(&genesis);
        let mut store =
            Store::open(&root.join("ledger"), &genesis, chain, Limits::default()).unwrap();
        store
            .accept_history([51; 32], &branch(&genesis, 51, count), NOW)
            .unwrap();
        let peer = SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes();
        let config = serde_json::to_vec(
            &json!({"listen":"127.0.0.1:0","neighbors":[],"offline_peers":[hex::encode(peer)]}),
        )
        .unwrap();
        let network = Network::open_with_budget(
            &root.join("contact"),
            chain,
            Some(&config),
            Budget {
                packets,
                ..Budget::default()
            },
        )
        .unwrap();
        (root, genesis, store, network, peer)
    }

    fn cursor(network: &Network, peer: Hash) -> Hash {
        network.offline_history_hints().unwrap().0[&peer]
    }

    #[test]
    fn changed_selected_branch_restarts_at_genesis_not_new_tip() {
        let (_, genesis, mut store, mut network, peer) = fixture(2, 64);
        network.offer_offline_history(&store).unwrap();
        let old_tip = store.ledger().tip().id();
        assert_eq!(cursor(&network, peer), old_tip);
        let winning = branch(&genesis, 53, 3);
        for (index, raw) in winning.iter().enumerate() {
            let mut operation = [53; 32];
            operation[31] = index as u8;
            store.accept(operation, raw, NOW).unwrap();
        }
        assert_ne!(store.ledger().tip().id(), old_tip);
        network.offer_offline_history(&store).unwrap();
        assert_eq!(cursor(&network, peer), store.ledger().tip().id());
        for raw in &winning {
            let packet = network
                .carriage
                .queued_copy(peer_id(peer), 3, raw)
                .unwrap()
                .expect("every genesis-rooted winning dependency was offered");
            assert_eq!(packet.payload(), raw);
        }
    }

    #[test]
    fn full_queue_never_advances_past_the_first_unoffered_block() {
        for budget in [1, 3] {
            let (_, _, store, mut network, peer) = fixture(4, budget);
            let selected = store.selected_ids().unwrap();
            assert!(matches!(
                network.offer_offline_history(&store),
                Err(OfflineHistoryError::Contact(_))
            ));
            assert_eq!(cursor(&network, peer), selected[budget]);
            let before: Vec<_> = selected[1..=budget]
                .iter()
                .map(|id| {
                    let raw = store.get_retained_block(*id).unwrap();
                    network
                        .carriage
                        .queued_copy(peer_id(peer), 3, &raw)
                        .unwrap()
                        .unwrap()
                })
                .collect();
            assert!(matches!(
                network.offer_offline_history(&store),
                Err(OfflineHistoryError::Contact(_))
            ));
            assert_eq!(cursor(&network, peer), selected[budget]);
            for packet in before {
                assert_eq!(
                    network.carriage.packet(packet.id()).unwrap().unwrap().raw(),
                    packet.raw()
                );
            }
            assert!(store.storage_ready());
        }
    }

    #[test]
    fn malformed_or_unadmitted_warm_hints_refuse_before_scheduling() {
        for wrong_peer in [false, true] {
            let (root, _, store, mut network, peer) = fixture(1, 64);
            let unexpected = SigningKey::from_bytes(&[54; 32]).verifying_key().to_bytes();
            let key = if wrong_peer { unexpected } else { peer };
            let tip = store.ledger().tip().id();
            let bytes = if wrong_peer { &tip[..] } else { &tip[..31] };
            network
                .carriage
                .db
                .execute(
                    "INSERT INTO offline_history VALUES(?1,?2)",
                    params![key.as_slice(), bytes],
                )
                .unwrap();
            let database = root.join("contact/custody/carriage.sqlite3");
            let before = fs::read(&database).unwrap();
            assert!(matches!(
                network.offer_offline_history(&store),
                Err(OfflineHistoryError::Contact(_))
            ));
            assert_eq!(fs::read(&database).unwrap(), before);
        }
    }
}
