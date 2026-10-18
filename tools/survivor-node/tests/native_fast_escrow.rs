//! Fresh NO-VALUE native execution and real nonce search with public fixture keys.
//! Logical block timestamps are not a physical elapsed-time or custody qualification.
use ed25519_dalek::{Signer, SigningKey};
use rld_survivor_node::{
    kernel::fast,
    kernel::{self, Hash},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const NOW: u64 = 2_000_000_000;
struct ReplayChild {
    process: Option<std::process::Child>,
    terminal: std::path::PathBuf,
}
impl Drop for ReplayChild {
    fn drop(&mut self) {
        if let Some(child) = self.process.as_mut() {
            let _ = child.kill();
            let result = child.wait();
            let _=std::fs::write(&self.terminal,serde_json::json!({"pid":child.id(),"forced_stop":true,"status":format!("{result:?}")}).to_string());
        }
    }
}
fn replay_process(
    label: &str,
    genesis: &std::path::Path,
    pin: Hash,
    archive: &std::path::Path,
    deadline: Instant,
) -> std::process::Output {
    assert!(Instant::now() < deadline, "original180 process start");
    let directory = genesis.parent().unwrap();
    let stdout = directory.join(format!("{label}.stdout.json"));
    let stderr = directory.join(format!("{label}.stderr.log"));
    let output = |path: &std::path::Path| {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).unwrap()
    };
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_rld-fast-escrow-candidate"))
        .arg(genesis)
        .arg(hex::encode(pin))
        .arg(archive)
        .stdout(output(&stdout))
        .stderr(output(&stderr))
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut child = ReplayChild {
        process: Some(child),
        terminal: directory.join(format!("{label}.terminal.json")),
    };
    let status = loop {
        if let Some(status) = child.process.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "original180 replay process deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    child.process.take();
    std::fs::write(&child.terminal,serde_json::json!({"pid":pid,"exit_code":status.code(),"success":status.success(),"forced_stop":false}).to_string()).unwrap();
    std::process::Output {
        status,
        stdout: std::fs::read(stdout).unwrap(),
        stderr: std::fs::read(stderr).unwrap(),
    }
}
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/native-fast-escrow-v1-vectors.json"
    ))
    .unwrap()
}
fn raw(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}
fn keys() -> [SigningKey; 2] {
    let mut k = [
        SigningKey::from_bytes(&[101; 32]),
        SigningKey::from_bytes(&[102; 32]),
    ];
    k.sort_by_key(|k| k.verifying_key().to_bytes());
    k
}
fn tag(s: &str) -> Vec<u8> {
    [b"RLD-FAST-ESCROW-1/".as_slice(), s.as_bytes(), &[0]].concat()
}
fn hash(s: &str, raw: &[u8]) -> Hash {
    Sha256::digest([tag(s), raw.to_vec()].concat()).into()
}
fn out(id: Hash, i: u16) -> Vec<u8> {
    [id.to_vec(), i.to_be_bytes().to_vec()].concat()
}
fn fresh() -> (Vec<u8>, fast::Ledger) {
    let mut genesis = raw(&vectors(), "genesis_hex");
    getrandom::getrandom(&mut genesis[13..45]).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    genesis[45..53].copy_from_slice(&(now - 2_000_000).to_be_bytes());
    let ledger = fast::Ledger::from_genesis(&genesis, fast::genesis_id(&genesis), 100_000).unwrap();
    (genesis, ledger)
}
fn mine(ledger: &mut fast::Ledger, miner: Hash, ops: Vec<Vec<u8>>, deadline: Instant) -> Vec<u8> {
    let mut job = ledger
        .mining_job(miner, ops, ledger.tip().timestamp() + 600, NOW)
        .unwrap();
    loop {
        assert!(Instant::now() < deadline, "original180 native fast scope");
        if let (Some(raw), _) = job.search(4096) {
            ledger.execute(&raw, NOW).unwrap();
            return raw;
        }
    }
}
fn transfer(
    chain: Hash,
    key: &SigningKey,
    input: &[u8],
    outputs: &[(Hash, u128)],
    fee: u128,
) -> Vec<u8> {
    let mut u = 1u16.to_be_bytes().to_vec();
    u.extend(chain);
    u.extend(key.verifying_key().to_bytes());
    u.extend(1u16.to_be_bytes());
    u.extend(input);
    u.extend((outputs.len() as u16).to_be_bytes());
    for (k, v) in outputs {
        u.extend(k);
        u.extend(v.to_be_bytes());
    }
    u.extend(fee.to_be_bytes());
    u.extend(u128::MAX.to_be_bytes());
    let signature = key.sign(&[b"RLD-SURVIVOR-1/TRANSFER\0".as_slice(), u.as_slice()].concat());
    let mut op = vec![0];
    op.extend(&u);
    op.extend(signature.to_bytes());
    op
}
fn txid(op: &[u8]) -> Hash {
    Sha256::digest([b"RLD-SURVIVOR-1/TXID\0".as_slice(), &op[1..op.len() - 64]].concat()).into()
}
fn open(chain: Hash, inputs: [Vec<u8>; 2], change: [u128; 2]) -> Vec<u8> {
    let k = keys();
    let mut u = vec![0, 1, 0, 1];
    u.extend(chain);
    u.extend([19; 32]);
    for k in &k {
        u.extend(k.verifying_key().to_bytes());
    }
    for p in [600u128, 400] {
        u.extend(p.to_be_bytes());
    }
    for (n, f) in [(6u64, 2u128), (5, 3)] {
        u.extend(n.to_be_bytes());
        u.extend(f.to_be_bytes());
    }
    for v in [1u128, 1, change[0], change[1], u128::MAX] {
        u.extend(v.to_be_bytes());
    }
    for input in inputs {
        u.extend(1u16.to_be_bytes());
        u.extend(input);
    }
    let msg = [tag("OPEN"), u.clone()].concat();
    let mut op = vec![1];
    op.extend(u);
    for k in k {
        op.extend(k.sign(&msg).to_bytes());
    }
    op
}
fn certificate(context: &[u8], sequence: u64, balances: [u128; 2], slots: [u64; 2]) -> Vec<u8> {
    let mut u = context[..68].to_vec();
    u.extend(sequence.to_be_bytes());
    for b in balances {
        u.extend(b.to_be_bytes());
    }
    for n in slots {
        u.extend(n.to_be_bytes());
    }
    let digest = Sha256::digest([b"RLD-FAST-FEE-CLAIM-1/CONTEXT\0".as_slice(), context].concat());
    let msg = [
        b"RLD-FAST-FEE-CLAIM-1/STATE\0".as_slice(),
        digest.as_slice(),
        u.as_slice(),
    ]
    .concat();
    for k in keys() {
        u.extend(k.sign(&msg).to_bytes());
    }
    u
}
fn action(
    chain: Hash,
    kind: u8,
    channel: Hash,
    key: &SigningKey,
    fee_input: (&[u8], u128),
    cert: &[u8],
    nonce: u8,
) -> Vec<u8> {
    let (input, change) = fee_input;
    let mut u = vec![0, 1, 0, 1];
    u.extend(chain);
    u.extend([nonce; 32]);
    u.extend(channel);
    u.extend(key.verifying_key().to_bytes());
    for n in [1u128, change, u128::MAX] {
        u.extend(n.to_be_bytes());
    }
    u.extend(1u16.to_be_bytes());
    u.extend(input);
    u.extend((cert.len() as u16).to_be_bytes());
    u.extend(cert);
    let signature = key.sign(&[tag("ACTION"), vec![kind], u.clone()].concat());
    let mut op = vec![kind];
    op.extend(u);
    op.extend(signature.to_bytes());
    op
}

#[test]
fn canonical_codec_vectors_are_not_funded_money_and_cannot_activate_survivor() {
    let v = vectors();
    let genesis = raw(&v, "genesis_hex");
    let pin = fast::genesis_id(&genesis);
    assert_eq!(hex::encode(pin), v["chain_id"]);
    assert!(kernel::Ledger::from_genesis(&genesis, pin, 1000).is_err());
    let ledger = fast::Ledger::from_genesis(&genesis, pin, 1000).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let op = raw(case, "operation_hex");
        assert_eq!(hex::encode(fast::operation_id(&op)), case["operation_id"]);
        fast::validate_operation(&op, pin).unwrap();
        let signatures = if op[0] == 1 { 128 } else { 64 };
        assert_eq!(op[1..op.len() - signatures], raw(case, "unsigned_hex"));
        for n in [0, op.len() - 1] {
            assert!(fast::validate_operation(&op[..n], pin).is_err());
        }
        let mut bad = op.clone();
        bad.push(0);
        assert!(fast::validate_operation(&bad, pin).is_err());
        let mut bad = op.clone();
        bad[op.len() - 1] ^= 1;
        assert!(fast::validate_operation(&bad, pin).is_err());
        if op[0] == 2 {
            let mut changed_kind = op.clone();
            changed_kind[0] = 5;
            assert!(fast::validate_operation(&changed_kind, pin).is_err());
        }
        assert!(ledger
            .mining_job(
                keys()[0].verifying_key().to_bytes(),
                vec![op],
                ledger.tip().timestamp() + 600,
                NOW
            )
            .is_err());
    }
    assert_eq!(
        (ledger.issued(), ledger.locked(), ledger.active_channels()),
        (0, 0, 0)
    );
    let baseline: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let old = raw(&baseline["genesis"], "manifest_hex");
    assert!(fast::Ledger::from_genesis(&old, kernel::genesis_id(&old), 1000).is_err());
    let mut malformed = genesis.clone();
    malformed[12] = 1;
    assert!(fast::Ledger::from_genesis(&malformed, fast::genesis_id(&malformed), 1000).is_err());
    let mut monetary = genesis.clone();
    monetary[105] ^= 1;
    assert!(fast::Ledger::from_genesis(&monetary, fast::genesis_id(&monetary), 1000).is_err());
}

#[test]
fn native_funding_old_state_claims_unilateral_settlement_maturity_and_full_replay() {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(180);
    let (genesis, mut ledger) = fresh();
    let k = keys();
    let a = k[0].verifying_key().to_bytes();
    let b = k[1].verifying_key().to_bytes();
    let miner = SigningKey::from_bytes(&[103; 32]);
    let m = miner.verifying_key().to_bytes();
    let chain = ledger.chain_id();
    let mut history = Vec::new();
    for _ in 0..100 {
        history.push(mine(&mut ledger, a, vec![], deadline));
    }
    let (input, coin) = ledger
        .coins()
        .iter()
        .find(|(_, c)| c.owner == a && c.maturity <= 101)
        .unwrap();
    let split = transfer(
        chain,
        &k[0],
        input,
        &[(a, 2000), (b, 2000), (a, coin.amount - 4001)],
        1,
    );
    let splitid = txid(&split);
    history.push(mine(&mut ledger, a, vec![split], deadline));
    let parent = ledger.clone();
    let opening = open(chain, [out(splitid, 0), out(splitid, 1)], [1387, 1584]);
    let channel = fast::operation_id(&opening);
    let wrong_owners = open(chain, [out(splitid, 1), out(splitid, 0)], [1387, 1584]);
    assert!(ledger
        .mining_job(m, vec![wrong_owners], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    history.push(mine(&mut ledger, m, vec![opening.clone()], deadline));
    assert_eq!((ledger.locked(), ledger.active_channels()), (1027, 1));
    assert!(!ledger.coins().contains_key(&out(splitid, 0)));
    assert!(!ledger.coins().contains_key(&out(splitid, 1)));
    assert_eq!(
        ledger.coins().values().map(|c| c.amount).sum::<u128>() + ledger.locked(),
        ledger.issued()
    );
    let double = transfer(chain, &k[0], &out(splitid, 0), &[(a, 1999)], 1);
    assert!(ledger
        .mining_job(a, vec![double], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    let context = ledger.fee_context(channel).unwrap();
    assert_eq!(&context[132..164], &m);
    let mut sibling = parent.clone();
    let mut job = sibling
        .mining_job(m, vec![opening], sibling.tip().timestamp() + 601, NOW)
        .unwrap();
    loop {
        if let (Some(raw), _) = job.search(4096) {
            sibling.execute(&raw, NOW).unwrap();
            break;
        }
    }
    assert_ne!(sibling.fee_context(channel).unwrap(), context);
    let s1 = certificate(&context, 1, [530, 470], [1, 0]);
    let s2 = certificate(&context, 2, [555, 445], [1, 1]);
    let s3 = certificate(&context, 3, [600, 400], [0, 3]);
    let wrong_birth = action(chain, 2, channel, &k[0], (&out(channel, 0), 1386), &s1, 21);
    assert!(sibling
        .mining_job(a, vec![wrong_birth], sibling.tip().timestamp() + 600, NOW)
        .is_err());
    let close = action(chain, 2, channel, &k[0], (&out(channel, 0), 1386), &[], 22);
    let closeid = fast::operation_id(&close);
    history.push(mine(&mut ledger, a, vec![close], deadline));
    let close_height = ledger.tip().height();
    // Valid work and a valid first debit cannot let a later invalid complete
    // fee certificate commit a partial block or spend its action-fee input.
    let fee_input = out(splitid, 2);
    let amount = ledger.coins()[&fee_input].amount;
    let ordinary = transfer(chain, &k[0], &fee_input, &[(a, amount - 1)], 1);
    let mut invalid = s1.clone();
    invalid[251] ^= 1;
    let invalid_action = (1..=255u8)
        .map(|nonce| {
            action(
                chain,
                4,
                channel,
                &k[0],
                (&out(closeid, 0), 1385),
                &invalid,
                nonce,
            )
        })
        .find(|op| fast::operation_id(op) > fast::operation_id(&ordinary))
        .unwrap();
    let mut temporary = ledger.clone();
    let empty = mine(&mut temporary, a, vec![], deadline);
    let mut malicious = empty[..268].to_vec();
    malicious.extend(2u16.to_be_bytes());
    for op in [ordinary, invalid_action] {
        malicious.extend((op.len() as u32).to_be_bytes());
        malicious.extend(op);
    }
    let commitment = hash("TRANSACTIONS", &malicious[268..]);
    malicious[188..220].copy_from_slice(&commitment);
    remine(&mut malicious);
    let before = ledger.tip().clone();
    assert!(ledger
        .execute(&malicious, NOW)
        .unwrap_err()
        .contains("signature"));
    assert_eq!(ledger.tip(), &before);
    assert_eq!(ledger.coins()[&fee_input].amount, amount);
    assert_eq!(ledger.coins()[&out(closeid, 0)].amount, 1386);
    assert_eq!(ledger.locked(), 1027);
    let challenge1 = action(chain, 3, channel, &k[1], (&out(channel, 1), 1583), &s1, 23);
    let ci = fast::operation_id(&challenge1);
    history.push(mine(&mut ledger, a, vec![challenge1], deadline));
    let challenge3 = action(chain, 3, channel, &k[1], (&out(ci, 0), 1582), &s3, 24);
    let c3 = fast::operation_id(&challenge3);
    history.push(mine(&mut ledger, a, vec![challenge3], deadline));
    let fee_claim = action(chain, 4, channel, &k[0], (&out(closeid, 0), 1385), &s2, 25);
    let fc = fast::operation_id(&fee_claim);
    history.push(mine(&mut ledger, a, vec![fee_claim], deadline));
    let settle = action(chain, 5, channel, &k[0], (&out(fc, 0), 1384), &[], 26);
    let sid = fast::operation_id(&settle);
    assert!(ledger
        .mining_job(b, vec![settle.clone()], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    while ledger.tip().height() < close_height + 2015 {
        history.push(mine(&mut ledger, a, vec![], deadline));
    }
    assert!(ledger
        .mining_job(b, vec![settle.clone()], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    history.push(mine(&mut ledger, a, vec![], deadline));
    assert_eq!(ledger.tip().height(), close_height + 2016);
    history.push(mine(&mut ledger, b, vec![settle], deadline));
    let settlement_height = ledger.tip().height();
    assert_eq!((ledger.locked(), ledger.active_channels()), (0, 0));
    assert!(ledger.fee_context(channel).is_err());
    assert_eq!(ledger.coins()[&out(sid, 1)].amount, 600);
    assert_eq!(ledger.coins()[&out(sid, 2)].amount, 400);
    assert_eq!(ledger.coins()[&out(sid, 3)].amount, 10);
    assert_eq!(ledger.coins()[&out(sid, 4)].amount, 6);
    let reward = &ledger.coins()[&out(sid, 5)];
    assert_eq!(
        (reward.owner, reward.amount, reward.maturity),
        (m, 11, settlement_height + 100)
    );
    let duplicate = action(chain, 5, channel, &k[1], (&out(c3, 0), 1581), &[], 27);
    assert!(ledger
        .mining_job(b, vec![duplicate], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    let spend = transfer(chain, &miner, &out(sid, 5), &[(a, 10)], 1);
    let spendid = txid(&spend);
    assert!(ledger
        .mining_job(a, vec![spend.clone()], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    while ledger.tip().height() < settlement_height + 98 {
        history.push(mine(&mut ledger, a, vec![], deadline));
    }
    assert!(ledger
        .mining_job(a, vec![spend.clone()], ledger.tip().timestamp() + 600, NOW)
        .is_err());
    history.push(mine(&mut ledger, a, vec![], deadline));
    history.push(mine(&mut ledger, a, vec![spend], deadline));
    assert_eq!(ledger.tip().height(), settlement_height + 100);
    assert_eq!(ledger.coins()[&out(spendid, 0)].amount, 10);
    assert!(!ledger.coins().contains_key(&out(sid, 5)));
    let mut cold = fast::Ledger::from_genesis(&genesis, chain, 100_000).unwrap();
    for block in &history {
        cold.execute(block, NOW).unwrap();
    }
    assert_eq!(cold.tip(), ledger.tip());
    assert_eq!(cold.coins().len(), ledger.coins().len());
    for (id, coin) in ledger.coins() {
        let replay = &cold.coins()[id];
        assert_eq!(
            (replay.owner, replay.amount, replay.maturity),
            (coin.owner, coin.amount, coin.maturity)
        );
    }
    assert_eq!(
        cold.coins().values().map(|c| c.amount).sum::<u128>(),
        cold.issued()
    );
    assert!(ledger.tip().preferred_to(sibling.tip()));
    let mut losing = fast::Ledger::from_genesis(&genesis, chain, 100_000).unwrap();
    for block in history.iter().take(101) {
        losing.execute(block, NOW).unwrap();
    }
    assert_eq!(losing.active_channels(), 0);
    assert!(losing.coins().contains_key(&out(splitid, 0)));
    assert_ne!(losing.tip().root(), ledger.tip().root());
    // Fresh private fixture archive, never a trusted serialized ledger. The
    // separate process independently reconstructs every native transition.
    let directory = std::env::temp_dir().join(format!(
        "rld-native-fast-{}-{}",
        std::process::id(),
        hex::encode(chain)
    ));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let genfile = directory.join("fresh.genesis");
    std::fs::write(&genfile, &genesis).unwrap();
    let archive = directory.join("blocks.archive");
    let mut file = std::fs::File::create(&archive).unwrap();
    use std::io::Write;
    for block in &history {
        file.write_all(&(block.len() as u32).to_be_bytes()).unwrap();
        file.write_all(block).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let replay = replay_process("replay", &genfile, chain, &archive, deadline);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let report: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(report["selected_tip"], hex::encode(ledger.tip().id()));
    assert_eq!(report["state_root"], hex::encode(ledger.tip().root()));
    assert_eq!(report["issued"], ledger.issued().to_string());
    assert_eq!(report["locked"], "0");
    assert_eq!(report["fast_service_qualified"], false);
    assert_eq!(report["independent_freshness"], false);
    eprintln!(
        "retained private no-value native archive: {}",
        directory.display()
    );
    eprintln!(
        "native fast execution: blocks={} elapsed={:?} timestamps=LOGICAL no_value_only=true",
        history.len(),
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(180));
}

fn remine(raw: &mut [u8]) {
    let target: Hash = raw[124..156].try_into().unwrap();
    for nonce in 0u128..1_000_000 {
        raw[252..268].copy_from_slice(&nonce.to_be_bytes());
        let id: Hash = Sha256::digest(hash("HEADER", &raw[..268])).into();
        if id <= target {
            return;
        }
    }
    panic!("bounded actual negative-block nonce search");
}
#[test]
fn actual_valid_work_cannot_authorize_unfunded_or_corrupted_operations_or_state() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let (genesis, ledger) = fresh();
    let a = keys()[0].verifying_key().to_bytes();
    let mut builder = ledger.clone();
    let valid = mine(&mut builder, a, vec![], deadline);
    let unknown = open(
        ledger.chain_id(),
        [out([21; 32], 0), out([22; 32], 0)],
        [31, 31],
    );
    let mut cases = vec![(unknown.clone(), "WAITING_FOR_INPUT")];
    let mut bad = unknown;
    let n = bad.len();
    bad[n - 1] ^= 1;
    cases.push((bad, "signature"));
    for (operation, error) in cases {
        let mut block = valid[..268].to_vec();
        block.extend(1u16.to_be_bytes());
        block.extend((operation.len() as u32).to_be_bytes());
        block.extend(operation);
        let bodyroot = hash("TRANSACTIONS", &block[268..]);
        block[188..220].copy_from_slice(&bodyroot);
        remine(&mut block);
        let mut recipient = ledger.clone();
        let before = recipient.tip().clone();
        assert!(recipient.execute(&block, NOW).unwrap_err().contains(error));
        assert_eq!(recipient.tip(), &before);
        assert!(recipient.coins().is_empty());
        assert_eq!(recipient.locked(), 0);
    }
    let mut wrongroot = valid.clone();
    wrongroot[220] ^= 1;
    remine(&mut wrongroot);
    let mut recipient = ledger.clone();
    assert!(recipient
        .execute(&wrongroot, NOW)
        .unwrap_err()
        .contains("state root"));
    assert_eq!(recipient.tip(), ledger.tip());
    let timestamp = u64::from_be_bytes(valid[84..92].try_into().unwrap());
    assert!(recipient
        .execute(&valid, timestamp - 7201)
        .unwrap_err()
        .contains("CLOCK_WAIT"));
    assert_eq!(recipient.tip(), ledger.tip());
    recipient.execute(&valid, NOW).unwrap();
    assert_eq!(recipient.tip(), builder.tip());
    let baseline: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/survivor-v1/vectors.json"
    ))
    .unwrap();
    let oldgen = raw(&baseline["genesis"], "manifest_hex");
    let mut old = kernel::Ledger::from_genesis(&oldgen, kernel::genesis_id(&oldgen), 1000).unwrap();
    assert!(old.execute(&valid).is_err());
    assert!(fast::Ledger::from_genesis(&genesis, kernel::genesis_id(&genesis), 1000).is_err());
}

#[test]
fn readonly_archive_cli_refuses_wrong_pin_truncation_excess_and_symlinks() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let (genesis, ledger) = fresh();
    let pin = ledger.chain_id();
    let directory = std::env::temp_dir().join(format!(
        "rld-native-fast-cli-{}-{}",
        std::process::id(),
        hex::encode(pin)
    ));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let genfile = directory.join("fresh.genesis");
    std::fs::write(&genfile, &genesis).unwrap();
    let empty = directory.join("empty.archive");
    std::fs::write(&empty, []).unwrap();
    let zero = replay_process("zero", &genfile, pin, &empty, deadline);
    assert!(zero.status.success());
    let report: Value = serde_json::from_slice(&zero.stdout).unwrap();
    assert_eq!(report["height"], "0");
    assert_eq!(report["issued"], "0");
    assert_eq!(report["liquid"], "0");
    assert_eq!(report["locked"], "0");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["fast_service_qualified"], false);
    let wrong = replay_process("wrong-pin", &genfile, [0; 32], &empty, deadline);
    assert!(!wrong.status.success());
    assert!(wrong.stdout.is_empty());
    let truncated = directory.join("truncated.archive");
    std::fs::write(&truncated, [0, 0]).unwrap();
    let missing = replay_process("missing", &genfile, pin, &truncated, deadline);
    assert!(!missing.status.success());
    assert!(String::from_utf8(missing.stderr)
        .unwrap()
        .contains("WAITING_FOR_HISTORY"));
    let large = directory.join("excess.archive");
    std::fs::File::create(&large)
        .unwrap()
        .set_len(256 * 1024 * 1024 + 1)
        .unwrap();
    let excess = replay_process("excess", &genfile, pin, &large, deadline);
    assert!(!excess.status.success());
    assert!(String::from_utf8(excess.stderr)
        .unwrap()
        .contains("RESOURCE_WAIT"));
    #[cfg(unix)]
    {
        let link = directory.join("archive-link");
        std::os::unix::fs::symlink(&empty, &link).unwrap();
        assert!(!replay_process("symlink", &genfile, pin, &link, deadline)
            .status
            .success());
    }
}
