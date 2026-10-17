//! Local encrypted whole-node snapshots. This format is not a consensus object.
//! Restore never overwrites a directory or treats a backup as its own freshness witness.
use crate::{
    carriage::{Budget, Carriage},
    kernel::{Hash, Result},
    network::Network,
    store::{Limits, Store},
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::SigningKey;
use rusqlite::{types::ValueRef, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
const MAX_FILE: usize = 256 * 1024 * 1024;
const HEADER: usize = 126;
fn err(e: impl std::fmt::Display) -> String {
    format!("RESOURCE_WAIT backup {e}")
}
fn ensure(ok: bool, s: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(s.into())
    }
}
pub(crate) fn db_head(db: &Connection, tables: &[(&str, &str)]) -> Result<Hash> {
    let mut digest = Sha256::new();
    digest.update(b"RLD-SURVIVOR-LOCAL-HEAD-1\0");
    for (table, order) in tables {
        digest.update((table.len() as u64).to_be_bytes());
        digest.update(table.as_bytes());
        let mut stmt = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
            .map_err(err)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).map_err(err)?;
        while let Some(row) = rows.next().map_err(err)? {
            digest.update([1]);
            digest.update((columns as u64).to_be_bytes());
            for i in 0..columns {
                match row.get_ref(i).map_err(err)? {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(n) => {
                        digest.update([1]);
                        digest.update(n.to_be_bytes());
                    }
                    ValueRef::Text(b) | ValueRef::Blob(b) => {
                        digest.update([
                            if matches!(row.get_ref(i).map_err(err)?, ValueRef::Text(_)) {
                                2
                            } else {
                                3
                            },
                        ]);
                        digest.update((b.len() as u64).to_be_bytes());
                        digest.update(b);
                    }
                    ValueRef::Real(_) => return Err("INVALID_ENCODING floating local state".into()),
                }
            }
        }
        digest.update([0]);
    }
    Ok(digest.finalize().into())
}
const LEDGER_TABLES: &[(&str, &str)] = &[
    ("binding", "singleton"),
    ("blocks", "id"),
    ("operations", "id"),
    ("wallet", "id"),
    ("submissions", "operation"),
    ("pool", "id"),
    ("changes", "revision"),
    ("reoffer", "height,block,ordinal"),
];
const CONTACT_TABLES: &[(&str, &str)] = &[
    ("identity", "one"),
    ("packets", "id"),
    ("receipts", "packet"),
    ("hop_receipts", "packet,sender"),
    ("cursors", "class"),
    ("equivocation", "origin,sequence"),
    ("offline_out", "peer,packet"),
    ("candidates", "key"),
    ("withdrawals", "packet"),
    ("peer_schedule", "peer"),
    ("peer_positions", "peer,class"),
];
pub fn state_head(store: &Store, network: &Network) -> Result<Hash> {
    combined(
        db_head(&store.db, LEDGER_TABLES)?,
        db_head(&network.carriage.db, CONTACT_TABLES)?,
    )
}
fn combined(a: Hash, b: Hash) -> Result<Hash> {
    Ok(crate::kernel::hash(
        "BACKUP-HEAD",
        &[a.as_slice(), b.as_slice()].concat(),
    ))
}
fn sync(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(err)
}
fn mkdir(path: &Path) -> Result<()> {
    fs::create_dir(path).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(err)?;
    }
    sync(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}
fn write(path: &Path, raw: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(err)?;
    f.write_all(raw).and_then(|_| f.sync_all()).map_err(err)?;
    sync(path.parent().ok_or("INVALID_ENCODING backup parent")?)
}
fn read(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    ensure(
        fs::symlink_metadata(path)
            .map_err(err)?
            .file_type()
            .is_file(),
        "INVALID_ENCODING backup regular file",
    )?;
    let mut b = Zeroizing::new(Vec::new());
    File::open(path)
        .map_err(err)?
        .take(max as u64 + 1)
        .read_to_end(&mut b)
        .map_err(err)?;
    ensure(b.len() <= max, "RESOURCE_WAIT backup file bound")?;
    Ok(b)
}
fn seal(raw: &[u8], chain: Hash, bundle: Hash, kind: u16, password: &[u8]) -> Result<Vec<u8>> {
    ensure(raw.len() <= MAX_FILE, "RESOURCE_WAIT backup record size")?;
    let mut random = [0; 44];
    getrandom::getrandom(&mut random).map_err(err)?;
    let mut header = b"RLDSBKP1".to_vec();
    header.extend(chain);
    header.extend(bundle);
    header.extend(kind.to_be_bytes());
    header.extend(random);
    header.extend((raw.len() as u64).to_be_bytes());
    let k = crate::keyfile::derived(password, &random[..32])?;
    let cipher =
        Aes256Gcm::new_from_slice(k.as_ref()).map_err(|_| "INVALID_CRYPTO backup cipher")?;
    header.extend(
        cipher
            .encrypt(
                Nonce::from_slice(&random[32..]),
                Payload {
                    msg: raw,
                    aad: &header,
                },
            )
            .map_err(|_| "INVALID_CRYPTO backup encryption")?,
    );
    Ok(header)
}
fn unseal(
    raw: &[u8],
    chain: Hash,
    bundle: Hash,
    kind: u16,
    password: &[u8],
    max: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure(
        raw.len() >= HEADER + 16 && raw.len() <= max + HEADER + 16,
        "INVALID_ENCODING backup record",
    )?;
    ensure(
        &raw[..8] == b"RLDSBKP1"
            && raw[8..40] == chain
            && raw[40..72] == bundle
            && raw[72..74] == kind.to_be_bytes(),
        "INVALID_CRYPTO backup binding",
    )?;
    let len = u64::from_be_bytes(raw[118..126].try_into().unwrap());
    ensure(
        len <= max as u64 && raw.len() == HEADER + len as usize + 16,
        "INVALID_ENCODING backup length",
    )?;
    let k = crate::keyfile::derived(password, &raw[74..106])?;
    let cipher =
        Aes256Gcm::new_from_slice(k.as_ref()).map_err(|_| "INVALID_CRYPTO backup cipher")?;
    Ok(Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&raw[106..118]),
                Payload {
                    msg: &raw[HEADER..],
                    aad: &raw[..HEADER],
                },
            )
            .map_err(|_| "INVALID_CRYPTO backup authentication")?,
    ))
}
fn destination(kind: u16) -> Result<PathBuf> {
    Ok(match kind {
        1 => "ledger.sqlite3".into(),
        2 => "contact/custody/carriage.sqlite3".into(),
        3 => "contact/contact.secret".into(),
        4 => "contact/tls.secret".into(),
        5 => "contact/config.json".into(),
        100..=163 => format!("keys/wallet-{}.key", kind - 100).into(),
        _ => return Err("UNSUPPORTED_VERSION backup record kind".into()),
    })
}
/// Caller runs this between native main-loop transitions. Workers can time out;
/// they cannot acknowledge a packet while its custody commit is absent.
pub fn create(
    store: &Store,
    network: &Network,
    target: &Path,
    password: &[u8],
    wallet_keys: &[PathBuf],
) -> Result<Hash> {
    ensure(wallet_keys.len() <= 64, "RESOURCE_WAIT backup key count")?;
    mkdir(target)?;
    write(&target.join("BUILDING"), b"RLD-SURVIVOR-BACKUP-1")?;
    let mut bundle = [0; 32];
    getrandom::getrandom(&mut bundle).map_err(err)?;
    let head = state_head(store, network)?;
    let chain = store.ledger().chain_id();
    let staging = target.join("staging");
    mkdir(&staging)?;
    let (contact, tls, config) = network.backup_material()?;
    let mut kinds = Vec::new();
    for kind in 1u16..=5 {
        let raw = match kind {
            1 | 2 => {
                let p = staging.join(format!("{kind}.sqlite3"));
                write(&p, &[])?;
                let db = if kind == 1 {
                    &store.db
                } else {
                    &network.carriage.db
                };
                db.backup(rusqlite::MAIN_DB, &p, None).map_err(err)?;
                sync(&p)?;
                read(&p, MAX_FILE)?
            }
            3 => contact.clone(),
            4 => tls.clone(),
            5 => Zeroizing::new(config.clone()),
            _ => unreachable!(),
        };
        write(
            &target.join(format!("{kind}.sealed")),
            &seal(&raw, chain, bundle, kind, password)?,
        )?;
        kinds.push(kind);
    }
    for (i, path) in wallet_keys.iter().enumerate() {
        let raw = read(path, 187)?;
        ensure(
            raw.len() == 187 && &raw[..8] == b"RLDSKEY1",
            "INVALID_ENCODING encrypted wallet key",
        )?;
        let kind = 100 + i as u16;
        write(
            &target.join(format!("{kind}.sealed")),
            &seal(&raw, chain, bundle, kind, password)?,
        )?;
        kinds.push(kind);
    }
    let manifest = json!({"format":"RLD-SURVIVOR-BACKUP-1","genesis":hex::encode(store.genesis_bytes()),"state_head":hex::encode(head),"kinds":kinds.iter().map(|n|n.to_string()).collect::<Vec<_>>(),"wallet_key_count":wallet_keys.len().to_string()});
    write(
        &target.join("manifest.sealed"),
        &seal(manifest.to_string().as_bytes(), chain, bundle, 0, password)?,
    )?;
    // Only our successful temporary database images are removed. Failed builds keep
    // their marker and residue and cannot be restored as complete snapshots.
    fs::remove_file(staging.join("1.sqlite3")).map_err(err)?;
    fs::remove_file(staging.join("2.sqlite3")).map_err(err)?;
    fs::remove_dir(&staging).map_err(err)?;
    fs::remove_file(target.join("BUILDING")).map_err(err)?;
    sync(target)?;
    Ok(head)
}
pub fn restore(
    source: &Path,
    target: &Path,
    genesis: &[u8],
    pin: Hash,
    password: &[u8],
    latest: Option<Hash>,
) -> Result<Hash> {
    ensure(
        !source.join("BUILDING").exists(),
        "FRESHNESS_UNKNOWN incomplete backup",
    )?;
    mkdir(target)?;
    write(&target.join("RESTORING"), b"RLD-SURVIVOR-BACKUP-1")?;
    let sealed = read(&source.join("manifest.sealed"), 65536 + HEADER + 16)?;
    ensure(
        sealed.len() >= HEADER + 16,
        "INVALID_ENCODING backup manifest",
    )?;
    let bundle: Hash = sealed[40..72].try_into().unwrap();
    let plain = unseal(&sealed, pin, bundle, 0, password, 65536)?;
    let manifest: Value =
        serde_json::from_slice(&plain).map_err(|_| "INVALID_ENCODING backup manifest")?;
    ensure(
        manifest["format"] == "RLD-SURVIVOR-BACKUP-1"
            && manifest["genesis"] == hex::encode(genesis),
        "WRONG_CHAIN backup genesis",
    )?;
    let head: Hash = hex::decode(
        manifest["state_head"]
            .as_str()
            .ok_or("INVALID_ENCODING backup head")?,
    )
    .map_err(err)?
    .try_into()
    .map_err(|_| "INVALID_ENCODING backup head")?;
    if let Some(expected) = latest {
        ensure(expected == head, "FRESHNESS_UNKNOWN stale backup")?;
    }
    let count: usize = manifest["wallet_key_count"]
        .as_str()
        .ok_or("INVALID_ENCODING key count")?
        .parse()
        .map_err(err)?;
    ensure(count <= 64, "RESOURCE_WAIT backup key count")?;
    let kinds: Vec<u16> = (1..=5).chain((0..count).map(|i| 100 + i as u16)).collect();
    ensure(
        manifest["kinds"] == json!(kinds.iter().map(|n| n.to_string()).collect::<Vec<_>>()),
        "INVALID_ENCODING backup inventory",
    )?;
    mkdir(&target.join("contact"))?;
    mkdir(&target.join("contact/custody"))?;
    mkdir(&target.join("keys"))?;
    for kind in kinds {
        let limit = match kind {
            1 | 2 => MAX_FILE,
            3 => 32,
            4 => 16384,
            5 => 65536,
            _ => 187,
        };
        let sealed = read(&source.join(format!("{kind}.sealed")), limit + HEADER + 16)?;
        let raw = unseal(&sealed, pin, bundle, kind, password, limit)?;
        write(&target.join(destination(kind)?), &raw)?;
    }
    let key = read(&target.join("contact/contact.secret"), 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(key.as_slice()).map_err(|_| "INVALID_CRYPTO restored contact key")?,
    );
    let key = SigningKey::from_bytes(&seed);
    let store = Store::open_restoring(target, genesis, pin, Limits::default())?;
    let custody = Carriage::open(
        &target.join("contact/custody"),
        pin,
        key.verifying_key().to_bytes(),
        Budget::default(),
    )?;
    ensure(
        combined(
            db_head(&store.db, LEDGER_TABLES)?,
            db_head(&custody.db, CONTACT_TABLES)?,
        )? == head,
        "INVALID_CRYPTO restored state head",
    )?;
    store
        .db
        .execute(
            "UPDATE restore_policy SET state=?1,ack_head=NULL WHERE one=1",
            [if latest.is_some() {
                "MATCHES_PROVIDED_HEAD"
            } else {
                "FRESHNESS_UNKNOWN"
            }],
        )
        .map_err(err)?;
    drop(custody);
    drop(store);
    fs::remove_file(target.join("RESTORING")).map_err(err)?;
    sync(target)?;
    Ok(head)
}
impl Store {
    pub fn freshness(&self) -> Result<String> {
        self.db
            .query_row("SELECT state FROM restore_policy WHERE one=1", [], |r| {
                r.get(0)
            })
            .map_err(err)
    }
    pub fn acknowledge_restore_risk(
        &self,
        expected_intent_head: Hash,
        acknowledge: bool,
    ) -> Result<()> {
        ensure(
            acknowledge,
            "FRESHNESS_UNKNOWN explicit risk acknowledgment required",
        )?;
        ensure(
            self.intent_head()? == expected_intent_head,
            "CONFLICT current intent head changed",
        )?;
        self.db
            .execute(
                "UPDATE restore_policy SET state='RISK_ACKNOWLEDGED',ack_head=?1 WHERE one=1",
                [expected_intent_head.as_slice()],
            )
            .map_err(err)?;
        Ok(())
    }
    pub fn intent_head(&self) -> Result<Hash> {
        db_head(&self.db, LEDGER_TABLES)
    }
}
