//! Local encrypted whole-node snapshots. This format is not a consensus object.
//! Restore never overwrites a directory or treats a backup as its own freshness witness.
use crate::{
    carriage::Carriage,
    kernel::{Hash, Result},
    network::Network,
    store::Store,
};
#[cfg(test)]
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    AeadInPlace, Aes256Gcm, Nonce,
};
use ed25519_dalek::SigningKey;
use rusqlite::{types::ValueRef, Connection};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
mod stream;
#[cfg(test)]
const MAX_FILE: usize = 256 * 1024 * 1024;
#[cfg(test)]
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
    ("history_batches", "operation"),
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
        &network.backup_material()?,
    )
}
fn combined(a: Hash, b: Hash, material: &crate::network::BackupMaterial) -> Result<Hash> {
    let material = crate::kernel::hash(
        "BACKUP-MATERIAL-2",
        &[
            crate::kernel::hash("BACKUP-CONTACT-2", &material.0).as_slice(),
            crate::kernel::hash("BACKUP-TLS-2", &material.1).as_slice(),
            crate::kernel::hash("BACKUP-CONFIG-2", &material.2).as_slice(),
        ]
        .concat(),
    );
    Ok(crate::kernel::hash(
        "BACKUP-HEAD-2",
        &[a.as_slice(), b.as_slice(), material.as_slice()].concat(),
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
#[cfg(test)]
fn seal(raw: &[u8], chain: Hash, bundle: Hash, kind: u16, password: &[u8]) -> Result<Vec<u8>> {
    ensure(raw.len() <= MAX_FILE, "RESOURCE_WAIT backup record size")?;
    let mut random = [0; 44];
    getrandom::getrandom(&mut random).map_err(err)?;
    // Allocate the complete exact record once. A separate ciphertext Vec would
    // otherwise coexist with the plaintext input and this final record. Until
    // encryption succeeds this buffer may contain plaintext, so zeroize it on
    // every error path; only authenticated ciphertext is moved out on success.
    let mut record = Zeroizing::new(Vec::new());
    record
        .try_reserve_exact(HEADER + raw.len() + 16)
        .map_err(err)?;
    record.extend(b"RLDSBKP1");
    record.extend(chain);
    record.extend(bundle);
    record.extend(kind.to_be_bytes());
    record.extend(random);
    record.extend((raw.len() as u64).to_be_bytes());
    record.extend(raw);
    let k = crate::keyfile::derived(password, &random[..32])?;
    let cipher =
        Aes256Gcm::new_from_slice(k.as_ref()).map_err(|_| "INVALID_CRYPTO backup cipher")?;
    let (header, body) = record.split_at_mut(HEADER);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&random[32..]), header, body)
        .map_err(|_| "INVALID_CRYPTO backup encryption")?;
    record.extend(tag);
    Ok(std::mem::take(&mut *record))
}
#[cfg(test)]
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
fn seal_record(
    path: &Path,
    input: impl Read,
    length: u64,
    chain: Hash,
    bundle: Hash,
    kind: u16,
    password: &[u8],
) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(path).map_err(err)?;
    stream::seal(input, &mut output, length, chain, bundle, kind, password)?;
    output.sync_all().map_err(err)?;
    sync(path.parent().ok_or("INVALID_ENCODING backup parent")?)
}
fn source(path: &Path) -> Result<File> {
    ensure(
        fs::symlink_metadata(path)
            .map_err(err)?
            .file_type()
            .is_file(),
        "INVALID_ENCODING backup regular file",
    )?;
    File::open(path).map_err(err)
}
fn restore_record(
    path: &Path,
    target: &Path,
    cap: u64,
    chain: Hash,
    bundle: Hash,
    kind: u16,
    password: &[u8],
) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(target).map_err(err)?;
    stream::open(
        source(path)?,
        &mut output,
        cap,
        chain,
        bundle,
        kind,
        password,
    )?;
    output.sync_all().map_err(err)?;
    sync(target.parent().ok_or("INVALID_ENCODING restored parent")?)
}
/// Caller runs between native transitions. Streamed chunks do not authorize a
/// snapshot; full native replay and the applicable freshness policy remain required.
pub fn create(
    store: &Store,
    network: &Network,
    target: &Path,
    password: &[u8],
    wallet_keys: &[PathBuf],
) -> Result<Hash> {
    ensure(wallet_keys.len() <= 64, "RESOURCE_WAIT backup key count")?;
    mkdir(target)?;
    write(&target.join("BUILDING"), b"RLD-SURVIVOR-BACKUP-2")?;
    let mut bundle = [0; 32];
    getrandom::getrandom(&mut bundle).map_err(err)?;
    let head = state_head(store, network)?;
    let chain = store.ledger().chain_id();
    let staging = target.join("staging");
    mkdir(&staging)?;
    let (contact, tls, config) = network.backup_material()?;
    let mut kinds = Vec::new();
    for kind in 1u16..=5 {
        let target = target.join(format!("{kind}.sealed"));
        if kind <= 2 {
            let p = staging.join(format!("{kind}.sqlite3"));
            write(&p, &[])?;
            let db = if kind == 1 {
                &store.db
            } else {
                &network.carriage.db
            };
            db.backup(rusqlite::MAIN_DB, &p, None).map_err(err)?;
            sync(&p)?;
            let length = fs::metadata(&p).map_err(err)?.len();
            let cap = if kind == 1 {
                store.resource_limits().database_bytes
            } else {
                network.resource_budget().bytes as u64
            };
            ensure(
                length <= cap,
                "RESOURCE_WAIT backup provisioned image bound",
            )?;
            seal_record(&target, source(&p)?, length, chain, bundle, kind, password)?;
        } else {
            let raw: &[u8] = match kind {
                3 => &contact,
                4 => &tls,
                5 => &config,
                _ => unreachable!(),
            };
            seal_record(
                &target,
                raw,
                raw.len() as u64,
                chain,
                bundle,
                kind,
                password,
            )?;
        }
        kinds.push(kind);
    }
    for (i, path) in wallet_keys.iter().enumerate() {
        let raw = read(path, 187)?;
        crate::keyfile::check_format(&raw)?;
        let kind = 100 + i as u16;
        seal_record(
            &target.join(format!("{kind}.sealed")),
            raw.as_slice(),
            raw.len() as u64,
            chain,
            bundle,
            kind,
            password,
        )?;
        kinds.push(kind);
    }
    let manifest = json!({"format":"RLD-SURVIVOR-BACKUP-2","genesis":hex::encode(store.genesis_bytes()),"state_head":hex::encode(head),"kinds":kinds.iter().map(|n|n.to_string()).collect::<Vec<_>>(),"wallet_key_count":wallet_keys.len().to_string()});
    let raw = manifest.to_string();
    seal_record(
        &target.join("manifest.sealed"),
        raw.as_bytes(),
        raw.len() as u64,
        chain,
        bundle,
        0,
        password,
    )?;
    fs::remove_file(staging.join("1.sqlite3")).map_err(err)?;
    fs::remove_file(staging.join("2.sqlite3")).map_err(err)?;
    fs::remove_dir(&staging).map_err(err)?;
    fs::remove_file(target.join("BUILDING")).map_err(err)?;
    sync(target)?;
    Ok(head)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    genesis: String,
    state_head: String,
    kinds: Vec<String>,
    wallet_key_count: String,
}
pub fn restore(
    source: &Path,
    target: &Path,
    genesis: &[u8],
    pin: Hash,
    password: &[u8],
    latest: Option<Hash>,
) -> Result<Hash> {
    restore_with_policy(
        source,
        target,
        genesis,
        pin,
        password,
        latest,
        crate::operating_policy::OperatingPolicy::default(),
    )
}
pub fn restore_with_policy(
    source_dir: &Path,
    target: &Path,
    genesis: &[u8],
    pin: Hash,
    password: &[u8],
    latest: Option<Hash>,
    policy: crate::operating_policy::OperatingPolicy,
) -> Result<Hash> {
    ensure(
        fs::symlink_metadata(source_dir).map_err(err)?.is_dir(),
        "INVALID_ENCODING backup source directory",
    )?;
    ensure(
        !source_dir.join("BUILDING").exists(),
        "FRESHNESS_UNKNOWN incomplete backup",
    )?;
    mkdir(target)?;
    write(&target.join("RESTORING"), b"RLD-SURVIVOR-BACKUP-2")?;
    let mut input = source(&source_dir.join("manifest.sealed"))?;
    let mut header = [0; stream::HEADER];
    input.read_exact(&mut header).map_err(err)?;
    let bundle: Hash = header[40..72].try_into().unwrap();
    std::io::Seek::rewind(&mut input).map_err(err)?;
    let mut plain = Zeroizing::new(Vec::new());
    stream::open(input, &mut *plain, 65536, pin, bundle, 0, password)?;
    let manifest: Manifest =
        serde_json::from_slice(&plain).map_err(|_| "INVALID_ENCODING backup manifest")?;
    ensure(
        manifest.format == "RLD-SURVIVOR-BACKUP-2" && manifest.genesis == hex::encode(genesis),
        "WRONG_CHAIN backup genesis",
    )?;
    let head: Hash = hex::decode(&manifest.state_head)
        .map_err(err)?
        .try_into()
        .map_err(|_| "INVALID_ENCODING backup head")?;
    ensure(
        manifest.state_head == hex::encode(head),
        "INVALID_ENCODING backup head",
    )?;
    if let Some(expected) = latest {
        ensure(expected == head, "FRESHNESS_UNKNOWN stale backup")?;
    }
    let count: usize = manifest
        .wallet_key_count
        .parse()
        .map_err(|_| "INVALID_ENCODING key count")?;
    ensure(count <= 64, "RESOURCE_WAIT backup key count")?;
    ensure(
        manifest.wallet_key_count == count.to_string(),
        "INVALID_ENCODING backup key count",
    )?;
    let kinds: Vec<u16> = (1..=5).chain((0..count).map(|i| 100 + i as u16)).collect();
    ensure(
        manifest.kinds == kinds.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        "INVALID_ENCODING backup inventory",
    )?;
    let mut expected = std::collections::BTreeSet::from(["manifest.sealed".to_string()]);
    expected.extend(kinds.iter().map(|n| format!("{n}.sealed")));
    for entry in fs::read_dir(source_dir).map_err(err)? {
        let entry = entry.map_err(err)?;
        ensure(
            entry.file_type().map_err(err)?.is_file(),
            "INVALID_ENCODING backup inventory file type",
        )?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "INVALID_ENCODING backup filename")?;
        ensure(
            expected.remove(&name),
            "INVALID_ENCODING unexpected backup object",
        )?;
    }
    ensure(expected.is_empty(), "MISSING_HISTORY backup object")?;
    mkdir(&target.join("contact"))?;
    mkdir(&target.join("contact/custody"))?;
    mkdir(&target.join("keys"))?;
    for kind in kinds {
        let cap = match kind {
            1 => policy.ledger().database_bytes,
            2 => policy.carriage().bytes as u64,
            3 => 32,
            4 => 16384,
            5 => 65536,
            _ => 187,
        };
        restore_record(
            &source_dir.join(format!("{kind}.sealed")),
            &target.join(destination(kind)?),
            cap,
            pin,
            bundle,
            kind,
            password,
        )?;
        if kind >= 100 {
            crate::keyfile::check_format(&read(&target.join(destination(kind)?), 187)?)?;
        }
    }
    let key = read(&target.join("contact/contact.secret"), 32)?;
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(key.as_slice()).map_err(|_| "INVALID_CRYPTO restored contact key")?,
    );
    let key = SigningKey::from_bytes(&seed);
    let store = Store::open_restoring(target, genesis, pin, policy.ledger())?;
    let custody = Carriage::open(
        &target.join("contact/custody"),
        pin,
        key.verifying_key().to_bytes(),
        policy.carriage(),
    )?;
    crate::network::verify_backup_material(
        &target.join("contact"),
        pin,
        key.verifying_key().to_bytes(),
    )?;
    let material = (
        read(&target.join("contact/contact.secret"), 32)?,
        read(&target.join("contact/tls.secret"), 16384)?,
        read(&target.join("contact/config.json"), 65536)?.to_vec(),
    );
    ensure(
        combined(
            db_head(&store.db, LEDGER_TABLES)?,
            db_head(&custody.db, CONTACT_TABLES)?,
            &material,
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

#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &[u8] = b"PUBLIC NO-VALUE RECORD PROBE";

    #[test]
    fn legacy_and_detached_record_methods_interoperate() {
        let payload = b"Deliberately public NO-VALUE record interoperability fixture.";
        // This fixed salt/nonce is restricted to this public test vector. Native
        // sealing still obtains fresh OS randomness for every independent record.
        let mut legacy = b"RLDSBKP1".to_vec();
        legacy.extend([1; 32]);
        legacy.extend([2; 32]);
        legacy.extend(1u16.to_be_bytes());
        legacy.extend([7; 44]);
        legacy.extend((payload.len() as u64).to_be_bytes());
        let key = crate::keyfile::derived(PASSWORD, &legacy[74..106]).unwrap();
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).unwrap();
        legacy.extend(
            cipher
                .encrypt(
                    Nonce::from_slice(&legacy[106..118]),
                    Payload {
                        msg: payload,
                        aad: &legacy,
                    },
                )
                .unwrap(),
        );
        assert_eq!(
            &*unseal(&legacy, [1; 32], [2; 32], 1, PASSWORD, MAX_FILE).unwrap(),
            payload
        );
        let new = seal(payload, [1; 32], [2; 32], 1, PASSWORD).unwrap();
        let key = crate::keyfile::derived(PASSWORD, &new[74..106]).unwrap();
        let reference = Aes256Gcm::new_from_slice(key.as_ref())
            .unwrap()
            .decrypt(
                Nonce::from_slice(&new[106..118]),
                Payload {
                    msg: &new[HEADER..],
                    aad: &new[..HEADER],
                },
            )
            .unwrap();
        assert_eq!(reference, payload);
        assert_eq!(new.len(), HEADER + payload.len() + 16);
    }

    #[test]
    fn changed_role_aad_password_length_or_tag_cannot_release_plaintext() {
        let raw = seal(
            b"PUBLIC NO-VALUE AUTHENTICATION INPUT",
            [1; 32],
            [2; 32],
            1,
            PASSWORD,
        )
        .unwrap();
        for offset in [8usize, 40, 73, 74, 106, HEADER, raw.len() - 1] {
            let mut changed = raw.clone();
            changed[offset] ^= 1;
            // Matching the edited role arguments must still fail the original
            // authenticated header; this exercises AAD rather than just pin checks.
            let chain = changed[8..40].try_into().unwrap();
            let bundle = changed[40..72].try_into().unwrap();
            let kind = u16::from_be_bytes(changed[72..74].try_into().unwrap());
            assert!(unseal(&changed, chain, bundle, kind, PASSWORD, MAX_FILE).is_err());
        }
        assert!(unseal(
            &raw,
            [1; 32],
            [2; 32],
            1,
            b"another public test passphrase",
            MAX_FILE
        )
        .is_err());
        assert!(unseal(
            &raw[..raw.len() - 1],
            [1; 32],
            [2; 32],
            1,
            PASSWORD,
            MAX_FILE
        )
        .is_err());
        let mut overlong = raw.clone();
        overlong.push(0);
        assert!(unseal(&overlong, [1; 32], [2; 32], 1, PASSWORD, MAX_FILE).is_err());
        assert!(unseal(&raw, [1; 32], [2; 32], 1, PASSWORD, 1).is_err());
    }

    /// The optional size is public test load, never a credential or monetary
    /// input. Default CI is small; explicit resource scopes retain their own
    /// original byte/time/memory bounds and exact executable/source inventory.
    #[test]
    fn record_resource_probe() {
        let bytes: usize = std::env::var("RLD_SURVIVOR_BACKUP_PROBE_BYTES")
            .ok()
            .map(|v| v.parse().expect("unsigned public probe size"))
            .unwrap_or(4097);
        assert!((1..=MAX_FILE).contains(&bytes));
        let root =
            std::env::temp_dir().join(format!("rld-survivor-record-probe-{}", std::process::id()));
        mkdir(&root).unwrap();
        let path = root.join("public-zero-payload");
        write(&path, &[]).unwrap();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(bytes as u64).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let raw = read(&path, MAX_FILE).unwrap();
        assert_eq!(raw.len(), bytes);
        println!(
            "{}",
            json!({"event":"RECORD_READ","bytes":bytes.to_string(),"capacity":raw.capacity().to_string()})
        );
        let sealed = seal(&raw, [1; 32], [2; 32], 1, PASSWORD).unwrap();
        println!(
            "{}",
            json!({"event":"RECORD_SEALED","bytes":sealed.len().to_string(),"capacity":sealed.capacity().to_string()})
        );
        write(&root.join("record.sealed"), &sealed).unwrap();
        let phase =
            std::env::var("RLD_SURVIVOR_BACKUP_PROBE_PHASE").unwrap_or_else(|_| "roundtrip".into());
        assert!(matches!(phase.as_str(), "seal" | "roundtrip"));
        if phase == "seal" {
            return;
        }
        // Creation and restoration are separate native operations. Do not keep
        // an artificial extra plaintext copy alive across both measured phases.
        drop(raw);
        let plain = unseal(&sealed, [1; 32], [2; 32], 1, PASSWORD, MAX_FILE).unwrap();
        assert_eq!(plain.len(), bytes);
        assert!(plain.iter().all(|b| *b == 0));
        println!(
            "{}",
            json!({"event":"RECORD_ROUNDTRIP_COMPLETE","bytes":plain.len().to_string(),"capacity":plain.capacity().to_string(),"fixture":"PUBLIC_NO_VALUE_ZERO_PAYLOAD","qualification":false})
        );
    }
    fn material_fixture(name: &str) -> (std::path::PathBuf, Vec<u8>, Hash, Store, Network) {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let mut g = hex::decode(v["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        getrandom::getrandom(&mut g[13..45]).unwrap();
        let pin = crate::kernel::genesis_id(&g);
        let root = std::env::temp_dir().join(format!(
            "rld-survivor-material-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let store =
            Store::open(&root.join("node"), &g, pin, crate::store::Limits::default()).unwrap();
        let network = Network::open(&root.join("node/contact"), pin, None).unwrap();
        (root, g, pin, store, network)
    }
    #[test]
    fn source_backup_refuses_replaced_retained_contact_and_tls_material() {
        for role in ["contact.secret", "tls.secret"] {
            let (root, _, _, store, network) = material_fixture(role);
            let path = root.join("node/contact").join(role);
            let mut raw = fs::read(&path).unwrap();
            let last = raw.len() - 1;
            raw[last] ^= 1;
            fs::write(path, raw).unwrap();
            assert!(state_head(&store, &network).is_err());
            let image = root.join("image");
            assert!(create(&store, &network, &image, PASSWORD, &[]).is_err());
            assert!(image.join("BUILDING").exists());
        }
    }
    #[test]
    fn a_valid_replacement_tls_key_cannot_match_the_retained_whole_node_head() {
        let (root, genesis, pin, store, network) = material_fixture("valid-credential-replacement");
        let image = root.join("image");
        let head = create(&store, &network, &image, PASSWORD, &[]).unwrap();
        let manifest = fs::read(image.join("manifest.sealed")).unwrap();
        let bundle: Hash = manifest[40..72].try_into().unwrap();
        let contact = network.backup_material().unwrap().0;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(contact.as_slice()).unwrap());
        let identity = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let (cert, key) = crate::tls::Material::generate(pin, identity).unwrap();
        let mut replacement = Zeroizing::new((cert.len() as u32).to_be_bytes().to_vec());
        replacement.extend(cert);
        replacement.extend(key.as_slice());
        fs::remove_file(image.join("4.sealed")).unwrap();
        seal_record(
            &image.join("4.sealed"),
            replacement.as_slice(),
            replacement.len() as u64,
            pin,
            bundle,
            4,
            PASSWORD,
        )
        .unwrap();
        let target = root.join("restored");
        let error = restore(&image, &target, &genesis, pin, PASSWORD, Some(head)).unwrap_err();
        assert_eq!(error, "INVALID_CRYPTO restored state head");
        assert!(target.join("RESTORING").exists());
        assert!(Store::open(&target, &genesis, pin, crate::store::Limits::default()).is_err());
    }
}
