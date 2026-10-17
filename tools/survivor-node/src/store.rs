//! Exclusive-writer SQLite persistence. Full genesis replay is the only source
//! of ledger authority. SQL records and block IDs are storage indexes only.
use crate::kernel::{block_id, Hash, Ledger, Result, Tip};
use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy)]
pub struct Limits {
    pub database_bytes: u64,
    pub coins: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            database_bytes: 256 * 1024 * 1024,
            coins: 1_000_000,
        }
    }
}
pub struct Store {
    pub(crate) db: Connection,
    _lease: File,
    root: PathBuf,
    genesis: Vec<u8>,
    ledger: Ledger,
    revision: u128,
    limits: Limits,
    poisoned: bool,
    last_clock: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub tip: Hash,
    pub revision: u128,
    pub selected: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitBoundary {
    Validated,
    IntentDurable,
    CommittedDurable,
}
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT {e}")
}
fn hash32(x: Vec<u8>) -> Result<Hash> {
    x.try_into().map_err(|_| "INVALID storage hash".into())
}
fn number(x: Vec<u8>) -> Result<u128> {
    Ok(u128::from_be_bytes(
        x.try_into().map_err(|_| "INVALID storage number")?,
    ))
}
fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn open_private(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).map_err(err)
}
impl Store {
    /// `genesis` and `pin` are supplied independently of the database. No peer or
    /// existing database chooses a currency. The directory is private local state.
    pub fn open(root: &Path, genesis: &[u8], pin: Hash, limits: Limits) -> Result<Self> {
        Self::open_internal(root, genesis, pin, limits, false)
    }
    pub(crate) fn open_restoring(
        root: &Path,
        genesis: &[u8],
        pin: Hash,
        limits: Limits,
    ) -> Result<Self> {
        Self::open_internal(root, genesis, pin, limits, true)
    }
    fn open_internal(
        root: &Path,
        genesis: &[u8],
        pin: Hash,
        limits: Limits,
        restoring: bool,
    ) -> Result<Self> {
        let initial = Ledger::from_genesis(genesis, pin, limits.coins)?;
        ensure(
            restoring || !root.join("RESTORING").exists(),
            "FRESHNESS_UNKNOWN interrupted restore",
        )?;
        if !root.exists() {
            fs::create_dir(root).map_err(err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(err)?;
            }
            File::open(
                root.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )
            .map_err(err)?
            .sync_all()
            .map_err(err)?;
        }
        ensure(
            fs::symlink_metadata(root).map_err(err)?.is_dir(),
            "INVALID store directory",
        )?;
        let lease = open_private(&root.join("writer.lock"))?;
        lease
            .try_lock_exclusive()
            .map_err(|_| "RESOURCE_WAIT writer already active")?;
        let dbpath = root.join("ledger.sqlite3");
        if dbpath.exists() {
            ensure(
                !fs::symlink_metadata(&dbpath)
                    .map_err(err)?
                    .file_type()
                    .is_symlink(),
                "INVALID database symlink",
            )?;
        }
        drop(open_private(&dbpath)?);
        let mut db = Connection::open(&dbpath).map_err(err)?;
        db.busy_timeout(Duration::from_secs(1)).map_err(err)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON;").map_err(err)?;
        let page: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(err)?;
        let page = u64::try_from(page).map_err(|_| "INVALID page size")?;
        ensure(page > 0, "INVALID page size")?;
        ensure(
            limits.database_bytes / page >= 32,
            "RESOURCE_WAIT database budget",
        )?;
        let pages = limits.database_bytes / page;
        let actual: i64 = db
            .query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))
            .map_err(err)?;
        ensure(
            actual > 0 && actual as u64 <= pages,
            "RESOURCE_WAIT existing database exceeds budget",
        )?;
        let integrity: String = db
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(err)?;
        ensure(integrity == "ok", "INVALID database integrity")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS binding (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format TEXT NOT NULL, genesis BLOB NOT NULL, tip BLOB NOT NULL, revision BLOB NOT NULL); CREATE TABLE IF NOT EXISTS blocks (id BLOB PRIMARY KEY, raw BLOB NOT NULL); CREATE TABLE IF NOT EXISTS operations (id BLOB PRIMARY KEY, raw BLOB NOT NULL, prior_tip BLOB NOT NULL, prior_revision BLOB NOT NULL, new_tip BLOB NOT NULL, new_root BLOB NOT NULL, revision BLOB NOT NULL, selected INTEGER NOT NULL, committed INTEGER NOT NULL CHECK(committed IN (0,1))); ").map_err(err)?;
        type BindingRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);
        let binding: Option<BindingRow> = db
            .query_row(
                "SELECT format,genesis,tip,revision FROM binding WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(err)?;
        let (tip, revision) = if let Some((format, g, t, r)) = binding {
            ensure(
                format == "RLD-SURVIVOR-STORE-3" && g == genesis,
                "INVALID store binding",
            )?;
            (hash32(t)?, number(r)?)
        } else {
            let count: i64 = db
                .query_row(
                    "SELECT (SELECT count(*) FROM blocks)+(SELECT count(*) FROM operations)",
                    [],
                    |r| r.get(0),
                )
                .map_err(err)?;
            ensure(count == 0, "INVALID missing binding")?;
            let tx = db.transaction().map_err(err)?;
            tx.execute(
                "INSERT INTO binding VALUES(1,?1,?2,?3,?4)",
                params![
                    "RLD-SURVIVOR-STORE-3",
                    genesis,
                    pin.as_slice(),
                    0u128.to_be_bytes().as_slice()
                ],
            )
            .map_err(err)?;
            tx.commit().map_err(err)?;
            (pin, 0)
        };
        File::open(root).map_err(err)?.sync_all().map_err(err)?;
        let mut s = Self {
            db,
            _lease: lease,
            root: root.to_path_buf(),
            genesis: genesis.to_vec(),
            ledger: initial,
            revision,
            limits,
            poisoned: false,
            last_clock: None,
        };
        s.observations_open()?;
        s.db.execute_batch("CREATE TABLE IF NOT EXISTS restore_policy (one INTEGER PRIMARY KEY CHECK(one=1),state TEXT NOT NULL,ack_head BLOB); INSERT OR IGNORE INTO restore_policy VALUES(1,'INTACT',NULL);").map_err(err)?;
        // Verify the complete ordered selected-transition chain and each retained
        // operation's exact block/result. Uncommitted intent never selects state.
        let mut previous = pin;
        let mut rev = 0u128;
        let mut current = s.ledger.clone();
        let mut heads = std::collections::BTreeMap::from([(0u128, pin)]);
        let mut stmt=s.db.prepare("SELECT id,raw,prior_tip,prior_revision,new_tip,new_root,revision,selected,committed FROM operations ORDER BY revision,selected DESC,committed DESC,id").map_err(err)?;
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            let id = hash32(row.get(0).map_err(err)?)?;
            ensure(id != [0; 32], "INVALID operation ID")?;
            let raw: Vec<u8> = row.get(1).map_err(err)?;
            ensure(
                s.get_block(block_id(&raw)?)? == raw,
                "INVALID operation bytes",
            )?;
            let parent: Hash = raw[36..68].try_into().unwrap();
            let mut candidate = if parent == current.tip().id() {
                current.clone()
            } else {
                s.replay(parent)?
            };
            candidate.execute(&raw)?;
            let nt = hash32(row.get(4).map_err(err)?)?;
            let nr = hash32(row.get(5).map_err(err)?)?;
            let selected: bool = row.get(7).map_err(err)?;
            let committed: bool = row.get(8).map_err(err)?;
            let prior = hash32(row.get(2).map_err(err)?)?;
            let pr = number(row.get(3).map_err(err)?)?;
            let r = number(row.get(6).map_err(err)?)?;
            ensure(
                heads.get(&pr) == Some(&prior),
                "INVALID operation prior revision",
            )?;
            let old = if prior == current.tip().id() {
                current.clone()
            } else {
                s.replay(prior)?
            };
            ensure(
                selected == candidate.tip().preferred_to(old.tip()),
                "INVALID retained selection",
            )?;
            let result = if selected { candidate.tip() } else { old.tip() };
            ensure(
                nt == result.id()
                    && nr == result.root()
                    && r == pr
                        .checked_add(u128::from(selected))
                        .ok_or("INVALID revision")?,
                "INVALID retained outcome",
            )?;
            if committed && selected {
                ensure(pr == rev && prior == previous, "INVALID revision chain")?;
                let stored: String =
                    s.db.query_row(
                        "SELECT body FROM changes WHERE revision=?1",
                        [r.to_be_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(err)?;
                let expected = s.branch_change_from(&old, pr, &candidate, &raw)?.0;
                let expected_body = serde_json::to_string(&expected).map_err(err)?;
                ensure(stored == expected_body, "INVALID_ENCODING retained change")?;
                rev = r;
                previous = nt;
                heads.insert(rev, nt);
                current = candidate;
            }
        }
        drop(rows);
        drop(stmt);
        ensure(previous == tip && rev == revision, "INVALID committed head")?;
        s.ledger = current;
        s.wallet_open()?;
        s.pool_open()?;
        Ok(s)
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
    pub fn revision(&self) -> u128 {
        self.revision
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn clock(&mut self, now: u64) -> Result<()> {
        ensure(!self.poisoned, "RESOURCE_WAIT restart required")?;
        if self.last_clock.is_some_and(|last| now < last) {
            return Err("CLOCK_WAIT backward clock".into());
        }
        self.last_clock = Some(now);
        ensure(
            self.ledger.tip().eligible(now),
            "CLOCK_WAIT future selected tip",
        )
    }
    pub fn get_block(&self, id: Hash) -> Result<Vec<u8>> {
        let raw: Vec<u8> = self
            .db
            .query_row("SELECT raw FROM blocks WHERE id=?1", [id.as_slice()], |r| {
                r.get(0)
            })
            .optional()
            .map_err(err)?
            .ok_or("MISSING_HISTORY")?;
        ensure(block_id(&raw)? == id, "INVALID object index")?;
        Ok(raw)
    }
    pub(crate) fn replay(&self, tip: Hash) -> Result<Ledger> {
        let pin = self.ledger.chain_id();
        let mut l = Ledger::from_genesis(&self.genesis, pin, self.limits.coins)?;
        let mut path = Vec::new();
        let mut id = tip;
        let mut expected = None;
        while id != pin {
            let raw = self.get_block(id)?;
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
        for id in path.into_iter().rev() {
            l.execute(&self.get_block(id)?)?;
        }
        Ok(l)
    }
    pub fn operation(&self, id: Hash) -> Result<Option<Outcome>> {
        let x: Option<(Vec<u8>, Vec<u8>, bool)> = self
            .db
            .query_row(
                "SELECT new_tip,revision,selected FROM operations WHERE id=?1 AND committed=1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(err)?;
        x.map(|(t, r, selected)| {
            Ok(Outcome {
                tip: hash32(t)?,
                revision: number(r)?,
                selected,
            })
        })
        .transpose()
    }
    /// Retains a fully validated object, then commits selection and exact operation
    /// result. Losing valid branches remain available, never merged into balances.
    pub fn accept(&mut self, operation: Hash, raw: &[u8], now: u64) -> Result<Outcome> {
        self.accept_observed(operation, raw, now, |_| {})
    }
    /// Instrumentation observes durable boundaries; it has no validation bypass.
    /// A panicking observer leaves mutation poisoned until full cold replay.
    pub fn accept_observed(
        &mut self,
        operation: Hash,
        raw: &[u8],
        now: u64,
        mut observe: impl FnMut(CommitBoundary),
    ) -> Result<Outcome> {
        self.clock(now)?;
        ensure(operation != [0; 32], "INVALID operation ID")?;
        let wallet_exists: bool = self
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM wallet WHERE id=?1 UNION ALL SELECT 1 FROM submissions WHERE operation=?1)",
                [operation.as_slice()],
                |r| r.get(0),
            )
            .map_err(err)?;
        ensure(!wallet_exists, "OPERATION_ID_CONFLICT")?;
        let existing: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT raw FROM operations WHERE id=?1",
                [operation.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(old) = &existing {
            ensure(old == raw, "OPERATION_ID_CONFLICT")?;
            if let Some(o) = self.operation(operation)? {
                return Ok(o);
            }
        }
        let id = block_id(raw)?;
        let parent: Hash = raw[36..68].try_into().unwrap();
        let mut candidate = if parent == self.ledger.tip().id() {
            self.ledger.clone()
        } else {
            self.replay(parent)?
        };
        candidate.execute(raw)?;
        ensure(candidate.tip().eligible(now), "CLOCK_WAIT future candidate")?;
        let selected = candidate.tip().preferred_to(self.ledger.tip());
        let next: Tip = if selected {
            candidate.tip()
        } else {
            self.ledger.tip()
        }
        .clone();
        let revision = self
            .revision
            .checked_add(u128::from(selected))
            .ok_or("RESOURCE_WAIT revision exhausted")?;
        let change = if selected {
            Some(self.branch_change(&candidate, raw)?)
        } else {
            None
        };
        self.poisoned = true;
        observe(CommitBoundary::Validated);
        self.poisoned = false;
        if existing.is_some() {
            let prior: (Vec<u8>, Vec<u8>) = self
                .db
                .query_row(
                    "SELECT prior_tip,prior_revision FROM operations WHERE id=?1",
                    [operation.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(err)?;
            ensure(
                hash32(prior.0)? == self.ledger.tip().id() && number(prior.1)? == self.revision,
                "CONFLICT pending prior changed",
            )?;
        } else {
            let prep = (|| -> Result<()> {
                let tx = self.db.transaction().map_err(err)?;
                let retained: Option<Vec<u8>> = tx
                    .query_row("SELECT raw FROM blocks WHERE id=?1", [id.as_slice()], |r| {
                        r.get(0)
                    })
                    .optional()
                    .map_err(err)?;
                if let Some(old) = retained {
                    ensure(old == raw, "INVALID object collision")?;
                } else {
                    tx.execute(
                        "INSERT INTO blocks VALUES(?1,?2)",
                        params![id.as_slice(), raw],
                    )
                    .map_err(err)?;
                }
                tx.execute(
                    "INSERT INTO operations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)",
                    params![
                        operation.as_slice(),
                        raw,
                        self.ledger.tip().id().as_slice(),
                        self.revision.to_be_bytes().as_slice(),
                        next.id().as_slice(),
                        next.root().as_slice(),
                        revision.to_be_bytes().as_slice(),
                        selected
                    ],
                )
                .map_err(err)?;
                tx.commit().map_err(err)?;
                Ok(())
            })();
            if let Err(e) = prep {
                self.poisoned = true;
                return Err(e);
            }
        }
        self.poisoned = true;
        observe(CommitBoundary::IntentDurable);
        self.poisoned = false;
        let commit = (|| -> Result<()> {
            let tx = self.db.transaction().map_err(err)?;
            tx.execute(
                "UPDATE operations SET committed=1 WHERE id=?1",
                [operation.as_slice()],
            )
            .map_err(err)?;
            if selected {
                tx.execute(
                    "UPDATE binding SET tip=?1,revision=?2 WHERE singleton=1",
                    params![next.id().as_slice(), revision.to_be_bytes().as_slice()],
                )
                .map_err(err)?;
                let (event, detached) =
                    change.as_ref().ok_or("INVALID_CONSENSUS missing change")?;
                tx.execute(
                    "INSERT INTO changes VALUES(?1,?2)",
                    params![revision.to_be_bytes().as_slice(), event.to_string()],
                )
                .map_err(err)?;
                for b in detached {
                    for (n, _) in crate::observations::transactions(b)?.iter().enumerate() {
                        tx.execute(
                            "INSERT OR IGNORE INTO reoffer VALUES(?1,?2,?3)",
                            params![block_id(b)?.as_slice(), n as u16, &b[68..84]],
                        )
                        .map_err(err)?;
                    }
                }
                // Included bytes remain in blocks and wallet/submission journals.
                // Removing this pool copy creates room for detached originals.
                for entry in event["attached"]
                    .as_array()
                    .ok_or("INVALID_ENCODING attached changes")?
                {
                    for id in entry["transactions"]
                        .as_array()
                        .ok_or("INVALID_ENCODING attached transactions")?
                    {
                        let id = hex::decode(id.as_str().ok_or("INVALID_ENCODING transaction id")?)
                            .map_err(err)?;
                        tx.execute("DELETE FROM pool WHERE id=?1", [id])
                            .map_err(err)?;
                    }
                }
            }
            tx.commit().map_err(err)?;
            Ok(())
        })();
        if let Err(e) = commit {
            self.poisoned = true;
            return Err(e);
        }
        if selected {
            self.ledger = candidate;
            self.revision = revision;
        }
        self.poisoned = true;
        observe(CommitBoundary::CommittedDurable);
        self.poisoned = false;
        Ok(Outcome {
            tip: next.id(),
            revision,
            selected,
        })
    }
}

impl Store {
    pub fn genesis_bytes(&self) -> &[u8] {
        &self.genesis
    }
    /// Selected IDs ordered genesis to tip, reconstructed from retained objects.
    pub fn selected_ids(&self) -> Result<Vec<Hash>> {
        self.ancestry_ids(self.ledger.tip().id())
    }
    pub(crate) fn ancestry_ids(&self, tip: Hash) -> Result<Vec<Hash>> {
        let mut ids = Vec::new();
        let mut id = tip;
        while id != self.ledger.chain_id() {
            ids.push(id);
            let raw = self.get_block(id)?;
            id = raw[36..68].try_into().unwrap();
            ensure(
                ids.len() as u64 <= self.limits.database_bytes / 270,
                "RESOURCE_WAIT locator index",
            )?;
        }
        ids.push(id);
        ids.reverse();
        Ok(ids)
    }
    pub fn locator(&self) -> Result<Vec<u8>> {
        let ids = self.selected_ids()?;
        let mut at = ids.len() - 1;
        let mut chosen = vec![ids[at]];
        for _ in 0..10 {
            if at == 0 {
                break;
            }
            at -= 1;
            chosen.push(ids[at]);
        }
        let mut offset = 2usize;
        while at > 0 && chosen.len() < 127 {
            at = at.saturating_sub(offset);
            chosen.push(ids[at]);
            offset = offset.saturating_mul(2);
        }
        if chosen.last() != Some(&ids[0]) {
            chosen.push(ids[0]);
        }
        let mut raw = (chosen.len() as u16).to_be_bytes().to_vec();
        for id in chosen {
            raw.extend(id)
        }
        Ok(raw)
    }
    pub fn successor_inventory(&self, locator: &[u8]) -> Result<Vec<u8>> {
        ensure(locator.len() >= 2, "INVALID_ENCODING locator")?;
        let n = u16::from_be_bytes(locator[..2].try_into().unwrap()) as usize;
        ensure(
            (1..=128).contains(&n) && locator.len() == 2 + n * 32,
            "INVALID_ENCODING locator",
        )?;
        let ids = self.selected_ids()?;
        let positions: std::collections::BTreeMap<_, _> =
            ids.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let mut start = 0;
        for raw in locator[2..].as_chunks::<32>().0 {
            let id: Hash = *raw;
            if let Some(i) = positions.get(&id) {
                start = i + 1;
                break;
            }
        }
        let mut selected: Vec<_> = ids.into_iter().skip(start).take(128).collect();
        selected.sort_unstable();
        let mut raw = (selected.len() as u16).to_be_bytes().to_vec();
        for id in selected {
            raw.push(if id == self.ledger.chain_id() { 1 } else { 3 });
            raw.extend(id);
        }
        Ok(raw)
    }
}
