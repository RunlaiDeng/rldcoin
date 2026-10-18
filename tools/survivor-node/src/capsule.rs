//! Streamed D02 evidence container. A digest binds bytes, never ledger authority.
//! Every record is executed from independently pinned genesis and normal Store
//! transitions execute it again before local monetary state can change.
use crate::{
    kernel::{decode_tx, Hash, Ledger, Result, Tip},
    store::{Limits, Store},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

const HEADER: usize = 96;
const FIXED: u64 = 213;
const DOMAIN: &[u8] = b"RLD-SURVIVOR-CAPSULE-1/CONTENT\0";

fn ensure(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn io_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        "WAITING_FOR_HISTORY incomplete capsule".into()
    } else {
        format!("RESOURCE_WAIT capsule {error}")
    }
}
fn read(file: &mut File, size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes).map_err(io_error)?;
    Ok(bytes)
}
fn hasher() -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest
}
fn take(file: &mut File, digest: &mut Sha256, size: usize) -> Result<Vec<u8>> {
    let bytes = read(file, size)?;
    digest.update(&bytes);
    Ok(bytes)
}
fn put(file: &mut File, digest: &mut Sha256, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes).map_err(io_error)?;
    digest.update(bytes);
    Ok(())
}
fn total(transaction: usize, history: u64, limit: u64) -> Result<u64> {
    let size = FIXED
        .checked_add(transaction as u64)
        .and_then(|n| n.checked_add(history))
        .ok_or("INVALID_ENCODING capsule length overflow")?;
    ensure(size <= limit, "RESOURCE_WAIT capsule byte budget")?;
    Ok(size)
}

struct Record {
    offset: u64,
    length: usize,
    digest: Hash,
}

/// Process-local result of complete native replay; never deserialized as trust.
pub struct Verified {
    file: File,
    intent: Vec<u8>,
    id: Hash,
    tip: Tip,
    records: Vec<Record>,
    bytes: u64,
}
impl Verified {
    pub fn intent(&self) -> &[u8] {
        &self.intent
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    pub fn observation(&self, now: Option<u64>) -> Value {
        json!({
            "format":"RLD-PAYMENT-CAPSULE-1","capsule_id":hex::encode(self.id),
            "transaction_hex":hex::encode(&self.intent),
            "carried_tip":hex::encode(self.tip.id()),
            "carried_height":self.tip.height().to_string(),
            "carried_work":hex::encode(self.tip.work_bytes()),
            "blocks":self.records.len().to_string(),"bytes":self.bytes.to_string(),
            "native_history_verified":true,
            "clock_eligible":now.map(|time|self.tip.eligible(time)),
            "local_ledger_acceptance":false,"independent_freshness":false,
            "confidence":"CONDITIONAL"
        })
    }
}

/// Authenticate one complete file without mutating a recipient or trusting its
/// selected chain. Genesis and pin are caller inputs, not capsule discoveries.
pub fn verify(
    path: &Path,
    genesis: &[u8],
    chain: Hash,
    limits: Limits,
    expected_intent: Option<&[u8]>,
) -> Result<Verified> {
    let mut ledger = Ledger::from_genesis(genesis, chain, limits.coins)?;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    ensure(metadata.is_file(), "INVALID_ENCODING capsule regular file")?;
    ensure(
        metadata.len() <= limits.database_bytes,
        "RESOURCE_WAIT capsule byte budget",
    )?;
    let mut file = File::open(path).map_err(io_error)?;
    let mut digest = hasher();
    let header = take(&mut file, &mut digest, HEADER)?;
    ensure(
        &header[..8] == b"RLDPCAP1",
        "INVALID_ENCODING capsule magic",
    )?;
    ensure(header[8..12] == [0, 1, 0, 1], "UNSUPPORTED_VERSION capsule")?;
    ensure(header[12..44] == chain, "WRONG_CHAIN capsule pin")?;
    let count = u64::from_be_bytes(header[44..52].try_into().unwrap());
    let length = u32::from_be_bytes(header[52..56].try_into().unwrap()) as usize;
    let history = u64::from_be_bytes(header[56..64].try_into().unwrap());
    let tip: Hash = header[64..96].try_into().unwrap();
    ensure(
        (248..=1638).contains(&length),
        "INVALID_ENCODING capsule intent size",
    )?;
    let size = total(length, history, limits.database_bytes)?;
    ensure(
        count <= history / 274 && ((count == 0) == (history == 0)),
        "INVALID_ENCODING capsule history count",
    )?;
    if metadata.len() < size {
        return Err("WAITING_FOR_HISTORY incomplete capsule".into());
    }
    ensure(
        metadata.len() == size,
        "INVALID_ENCODING capsule trailing bytes",
    )?;
    let intent = take(&mut file, &mut digest, length)?;
    decode_tx(&intent, chain)?;
    ensure(
        expected_intent.is_none_or(|expected| expected == intent),
        "INVALID_CRYPTO capsule changed expected intent",
    )?;
    ensure(
        take(&mut file, &mut digest, 85)? == genesis,
        "WRONG_CHAIN capsule genesis",
    )?;
    let mut records = Vec::new();
    let mut consumed = 0u64;
    for _ in 0..count {
        let n = take(&mut file, &mut digest, 4)?;
        let length = u32::from_be_bytes(n.try_into().unwrap()) as usize;
        ensure(
            (270..=262144).contains(&length),
            "INVALID_ENCODING capsule block size",
        )?;
        consumed = consumed
            .checked_add(4 + length as u64)
            .ok_or("INVALID_ENCODING capsule history overflow")?;
        ensure(
            consumed <= history,
            "INVALID_ENCODING capsule history length",
        )?;
        let offset = file.stream_position().map_err(io_error)?;
        let raw = take(&mut file, &mut digest, length)?;
        ledger.execute(&raw)?;
        records.push(Record {
            offset,
            length,
            digest: Sha256::digest(&raw).into(),
        });
    }
    ensure(
        consumed == history,
        "INVALID_ENCODING capsule history length",
    )?;
    ensure(
        ledger.tip().id() == tip,
        "INVALID_CONSENSUS capsule terminal tip",
    )?;
    let id: Hash = digest.finalize().into();
    ensure(read(&mut file, 32)? == id, "INVALID_CRYPTO capsule digest")?;
    let mut extra = [0];
    ensure(
        file.read(&mut extra).map_err(io_error)? == 0,
        "INVALID_ENCODING capsule trailing bytes",
    )?;
    Ok(Verified {
        file,
        intent,
        id,
        tip: ledger.tip().clone(),
        records,
        bytes: size,
    })
}

/// Stream a fresh file and replay every exported block; no source cache is
/// exported as balance authority. Failed partial output remains untouched.
pub fn export(store: &Store, intent: &[u8], path: &Path) -> Result<Hash> {
    ensure(store.storage_ready(), "RESOURCE_WAIT restart required")?;
    decode_tx(intent, store.ledger().chain_id())?;
    let ids = store.selected_ids()?;
    let mut history = 0u64;
    for id in ids.iter().skip(1) {
        let raw = store.get_block(*id)?;
        history = history
            .checked_add(4 + raw.len() as u64)
            .ok_or("RESOURCE_WAIT capsule history size")?;
        total(
            intent.len(),
            history,
            store.resource_limits().database_bytes,
        )?;
    }
    let size = total(
        intent.len(),
        history,
        store.resource_limits().database_bytes,
    )?;
    let mut header = Vec::with_capacity(HEADER);
    header.extend(b"RLDPCAP1");
    header.extend([0, 1, 0, 1]);
    header.extend(store.ledger().chain_id());
    header.extend(((ids.len() - 1) as u64).to_be_bytes());
    header.extend((intent.len() as u32).to_be_bytes());
    header.extend(history.to_be_bytes());
    header.extend(store.ledger().tip().id());
    let mut ledger = Ledger::from_genesis(
        store.genesis_bytes(),
        store.ledger().chain_id(),
        store.resource_limits().coins,
    )?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    let mut digest = hasher();
    put(&mut file, &mut digest, &header)?;
    put(&mut file, &mut digest, intent)?;
    put(&mut file, &mut digest, store.genesis_bytes())?;
    for id in ids.iter().skip(1) {
        let raw = store.get_block(*id)?;
        ledger.execute(&raw)?;
        put(&mut file, &mut digest, &(raw.len() as u32).to_be_bytes())?;
        put(&mut file, &mut digest, &raw)?;
    }
    ensure(
        ledger.tip().id() == store.ledger().tip().id(),
        "CONFLICT capsule source history changed",
    )?;
    let id: Hash = digest.finalize().into();
    file.write_all(&id).map_err(io_error)?;
    ensure(
        file.stream_position().map_err(io_error)? == size,
        "CONFLICT capsule source size changed",
    )?;
    file.sync_all().map_err(io_error)?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|directory| directory.sync_all())
    .map_err(io_error)?;
    Ok(id)
}

pub fn refresh(store: &Store, prior: &Path, output: &Path) -> Result<Hash> {
    let verified = verify(
        prior,
        store.genesis_bytes(),
        store.ledger().chain_id(),
        store.resource_limits(),
        None,
    )?;
    export(store, verified.intent(), output)
}

fn operation(domain: &[u8], capsule: Hash, index: u64, record: &[u8]) -> Hash {
    let mut digest = Sha256::new();
    digest.update(b"RLD-SURVIVOR-CAPSULE-1/");
    digest.update(domain);
    digest.update([0]);
    digest.update(capsule);
    digest.update(index.to_be_bytes());
    digest.update(Sha256::digest(record));
    digest.finalize().into()
}

/// Initial invalid evidence cannot mutate the store. An application I/O failure
/// can retain only native-validated prefix transitions, never a complete receipt.
pub fn import(
    store: &mut Store,
    path: &Path,
    expected_intent: Option<&[u8]>,
    now: u64,
) -> Result<Value> {
    ensure(store.storage_ready(), "RESOURCE_WAIT restart required")?;
    let mut verified = verify(
        path,
        store.genesis_bytes(),
        store.ledger().chain_id(),
        store.resource_limits(),
        expected_intent,
    )?;
    apply(store, &mut verified, now)
}

fn apply(store: &mut Store, verified: &mut Verified, now: u64) -> Result<Value> {
    ensure(verified.tip.eligible(now), "CLOCK_WAIT future capsule")?;
    for (index, record) in verified.records.iter().enumerate() {
        verified
            .file
            .seek(SeekFrom::Start(record.offset - 4))
            .map_err(io_error)?;
        let length = read(&mut verified.file, 4)?;
        ensure(
            u32::from_be_bytes(length.try_into().unwrap()) as usize == record.length,
            "INVALID_CRYPTO capsule reread length changed",
        )?;
        let raw = read(&mut verified.file, record.length)?;
        ensure(
            <Hash>::from(Sha256::digest(&raw)) == record.digest,
            "INVALID_CRYPTO capsule reread bytes changed",
        )?;
        store.accept(
            operation(b"BLOCK", verified.id, index as u64, &raw),
            &raw,
            now,
        )?;
    }
    store.submit_transaction(
        operation(b"SUBMIT", verified.id, 0, &verified.intent),
        &verified.intent,
        now,
    )?;
    Ok(json!({
        "format":"RLD-PAYMENT-CAPSULE-1","capsule_id":hex::encode(verified.id),
        "carried_tip":hex::encode(verified.tip.id()),
        "selected_tip":hex::encode(store.ledger().tip().id()),
        "revision":store.revision().to_string(),
        "transaction_hex":hex::encode(&verified.intent),
        "transaction":store.transfer_observation(&verified.intent)?,
        "complete_import":true,"confidence":"CONDITIONAL"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn changed_valid_record_after_verification_cannot_select_another_history() {
        // Only public NO-VALUE signatures and history, never production custody.
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/payment-capsule-v1-vectors.json"
        ))
        .unwrap();
        let consensus: Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/survivor-v1/vectors.json"
        ))
        .unwrap();
        let genesis = hex::decode(consensus["genesis"]["manifest_hex"].as_str().unwrap()).unwrap();
        let pin = crate::kernel::genesis_id(&genesis);
        let root = std::env::temp_dir().join(format!(
            "rld-capsule-reread-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("public.capsule");
        fs::write(
            &path,
            hex::decode(vectors["cases"][1]["capsule_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let mut verified = verify(&path, &genesis, pin, Limits::default(), None).unwrap();
        let replacement = hex::decode(
            consensus["recovery_branch_from_genesis"][0]["block_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replacement.len(), verified.records[0].length);
        let mut independently_valid = Ledger::from_genesis(&genesis, pin, 1000).unwrap();
        independently_valid.execute(&replacement).unwrap();
        let mut changed = OpenOptions::new().write(true).open(&path).unwrap();
        changed
            .seek(SeekFrom::Start(verified.records[0].offset))
            .unwrap();
        changed.write_all(&replacement).unwrap();
        changed.sync_all().unwrap();
        let mut recipient =
            Store::open(&root.join("recipient"), &genesis, pin, Limits::default()).unwrap();
        assert_eq!(
            apply(&mut recipient, &mut verified, 2_000_000_000).unwrap_err(),
            "INVALID_CRYPTO capsule reread bytes changed"
        );
        assert_eq!(recipient.ledger().tip().id(), pin);
        assert_eq!(recipient.revision(), 0);
        assert!(recipient.ledger().coins().is_empty());
    }
}
