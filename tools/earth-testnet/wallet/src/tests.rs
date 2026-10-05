use super::*;
use rld_core::{generate_identity, AdmissionHash32 as Hash, Amount};
use rld_fast_payments::{
    successor::{OpenChannel, OpenIntent},
    ChannelState, SignedState,
};
use rld_pow::{target_limit, Chain, Context};
use rld_value_successor::chain::{mine_batch, CandidateChain};

#[tokio::test]
async fn stalled_source_and_destination_release_wallet_with_verified_state_retained() {
    use rld_value_successor::destination::pow::{
        storage::DestinationPowStore, Context as DestinationContext,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().fallback(|| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        StatusCode::SERVICE_UNAVAILABLE
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let (mut w, root) = io_wallet(&format!("http://{addr}"));
    w.replay.isolated_fixture = false;
    w.replay.http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(25))
        .build()
        .unwrap();
    w.replay.fresh = true;
    let source_tip = w.replay.store.chain().tip();
    let started = std::time::Instant::now();
    assert!(w
        .replay
        .refresh()
        .await
        .unwrap_err()
        .to_string()
        .contains("时间预算"));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!w.replay.fresh && w.replay.error.is_some());
    assert_eq!(w.replay.store.chain().tip(), source_tip);
    let source = w.replay.store.chain();
    let context = DestinationContext {
        chain_id: Hash([72; 32]),
        source_policy: rld_value_successor::chain::ObservationPolicy {
            source_chain_id: source.chain_id(),
            accepted_v1_tip: source.v1_tip(),
            minimum_confirmations: 12,
            minimum_cumulative_work: rld_core::header_work(target_limit()),
        },
        started_at: 1_000_000,
        initial_target: target_limit(),
        source_finality: None,
        regional: None,
        migration: None,
    };
    let store =
        DestinationPowStore::open(&root.join("destination"), context, source, now().unwrap())
            .unwrap();
    let mut destination = destination::Replay {
        store,
        node: format!("http://{addr}"),
        authorization: Hash([73; 32]),
        fresh: true,
        checked: 0,
        isolated_fixture: false,
    };
    let destination_tip = destination.store.chain().tip();
    let started = std::time::Instant::now();
    assert!(destination
        .refresh(source, &w.replay.http)
        .await
        .unwrap_err()
        .to_string()
        .contains("时间预算"));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!destination.fresh);
    assert_eq!(destination.store.chain().tip(), destination_tip);
    drop(destination);
    drop(w);
    server.abort();
    let _ = server.await;
    std::fs::remove_dir_all(root).unwrap();
}
fn blank() -> CandidateChain {
    let v1 = Chain::new(Context {
        network_domain: "wallet-isolated-test".into(),
        zone_id: "fixture-only".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 0,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: target_limit(),
        regional: None,
    })
    .unwrap();
    CandidateChain::from_replayed_pow_chain(&v1).unwrap()
}
fn mine(c: &mut CandidateChain, miner: &str, commands: Vec<Command>) {
    let timestamp = 1_000_000 + (c.height() as u64 + 1) * 600;
    let mut block = c.template(miner.into(), timestamp, commands).unwrap();
    while !mine_batch(&mut block, 10000).unwrap() {}
    c.accept(block, timestamp).unwrap();
}
#[test]
fn exact_decimal_amounts_and_boundaries() {
    for (s, n) in [
        ("0", 0),
        ("1", chain::UNIT),
        ("0.000000000000000000000001", 1),
        ("12.345", 12 * chain::UNIT + 345 * 10u128.pow(21)),
    ] {
        assert_eq!(chain::amount(s).unwrap(), n);
        assert_eq!(chain::amount(&chain::format(n)).unwrap(), n);
    }
    for s in [
        "-1",
        "1e2",
        "+1",
        "00",
        "01.1",
        ".1",
        "1.",
        " 1",
        "1.0000000000000000000000001",
        "340282366920938463463374607431768211456",
    ] {
        assert!(chain::amount(s).is_err(), "{s}");
    }
}
#[test]
fn vault_roundtrip_wrong_password_tamper_and_key_binding() {
    let password = "correct-test-passphrase-only";
    let v = vault::Vault::create(password).unwrap();
    let bytes = serde_json::to_vec(&v).unwrap();
    let restored = vault::Vault::parse(&bytes).unwrap();
    assert_eq!(
        *v.unlock(password).unwrap(),
        *restored.unlock(password).unwrap()
    );
    assert!(restored.unlock("different-long-password").is_err());
    let mut value = serde_json::to_value(&v).unwrap();
    value["public_key"] = json!(generate_identity().public_key);
    assert!(serde_json::from_value::<vault::Vault>(value)
        .unwrap()
        .unlock(password)
        .is_err());
    let mut value = serde_json::to_value(&v).unwrap();
    value["ciphertext"] = json!("00".repeat(80));
    assert!(serde_json::from_value::<vault::Vault>(value)
        .unwrap()
        .unlock(password)
        .is_err());
    assert!(vault::Vault::parse(&vec![0; 4097]).is_err());
    assert!(vault::Vault::create("short").is_err());
}
#[test]
fn fresh_empty_identity_has_no_balance() {
    assert!(chain::coins(&blank()).unwrap().is_empty());
}
#[test]
fn maturity_transfer_fees_pending_and_reorg_reconcile() {
    let a = generate_identity();
    let b = generate_identity();
    let mut c = blank();
    mine(&mut c, &a.public_key, vec![]);
    assert!(chain::prepare(&c, &a.public_key, &b.public_key, 1, 1, &[]).is_err());
    for _ in 1..101 {
        mine(&mut c, &a.public_key, vec![]);
    }
    let mut tx = chain::prepare(&c, &a.public_key, &b.public_key, chain::UNIT, 1, &[]).unwrap();
    assert_eq!(tx.inputs.len(), 1);
    tx.signature = sign_bytes(&a.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    let cmd = Command::Transfer(tx.clone());
    let journal = vec![chain::Journal {
        command: cmd.clone(),
        created_at: 0,
    }];
    let reserved = chain::reserved(&c, &journal).unwrap();
    assert!(tx.inputs.iter().all(|p| reserved.contains(p)));
    let alternative = chain::prepare(&c, &a.public_key, &b.public_key, chain::UNIT, 1, &journal);
    assert!(alternative.is_err());
    let original = c.clone();
    mine(&mut c, &a.public_key, vec![cmd.clone()]);
    let coins = chain::coins(&c).unwrap();
    assert_eq!(
        coins
            .iter()
            .filter(|(_, x)| x.output.owner == b.public_key)
            .map(|(_, x)| x.output.amount.0)
            .sum::<u128>(),
        chain::UNIT
    );
    assert!(chain::reserved(&c, &journal).unwrap().is_empty());
    assert!(c
        .template(a.public_key.clone(), 1_000_000 + 103 * 600, vec![cmd])
        .is_err());
    let mut fork = original;
    mine(&mut fork, &b.public_key, vec![]);
    mine(&mut fork, &b.public_key, vec![]);
    for block in fork.best_blocks().unwrap() {
        c.accept(block.clone(), 1_000_000 + 103 * 600).unwrap();
    }
    assert_eq!(c.tip(), fork.tip());
    let coins = chain::coins(&c).unwrap();
    assert!(!coins.keys().any(|p| p.transaction == tx.id().unwrap()));
    assert!(chain::reserved(&c, &journal)
        .unwrap()
        .contains(&tx.inputs[0]));
    while c.height() < tx.valid_through_height {
        mine(&mut c, &a.public_key, vec![]);
    }
    assert!(chain::reserved(&c, &journal).unwrap().is_empty());
}
#[test]
fn sustained_channel_challenge_refund_export_and_settlement_reconcile() {
    let a = generate_identity();
    let b = generate_identity();
    let mut c = blank();
    for _ in 0..104 {
        mine(&mut c, &a.public_key, vec![]);
    }
    let (input, coin) = chain::coins(&c)
        .unwrap()
        .into_iter()
        .find(|(_, x)| x.spendable_height <= c.height())
        .unwrap();
    let intent = OpenIntent {
        chain_id: c.chain_id(),
        input,
        party_a: a.public_key.clone(),
        party_b: b.public_key.clone(),
        capacity: Amount(chain::UNIT),
        close_fee: Amount(1),
        opening_fee: Amount(1),
        change: Amount(coin.output.amount.0 - chain::UNIT - 1),
        valid_through_height: 120,
    };
    let funding = intent.funding().unwrap();
    let channel = funding.id().unwrap();
    let state = ChannelState::initial(&funding).unwrap();
    let sign = |state: ChannelState| {
        let bytes = state.signing_bytes(&funding).unwrap();
        SignedState {
            state,
            signature_a: sign_bytes(&a.secret_key, &bytes).unwrap(),
            signature_b: sign_bytes(&b.secret_key, &bytes).unwrap(),
        }
    };
    let initial = sign(state);
    let mut latest = initial.clone();
    // Each state is signed by both fixture parties and restored from serialized bytes.
    for n in 1..=1000u64 {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        let next = latest
            .state
            .propose_payment(
                &funding,
                &a.public_key,
                Amount(chain::UNIT / 10000),
                Hash(id),
            )
            .unwrap();
        latest = sign(next);
        latest.verify(&funding).unwrap();
        latest = serde_json::from_slice(&serde_json::to_vec(&latest).unwrap()).unwrap();
    }
    assert_eq!(latest.state.balance_b.0, chain::UNIT / 10);
    let open = OpenChannel {
        signature_a: sign_bytes(&a.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
        initial: initial.clone(),
    };
    mine(&mut c, &a.public_key, vec![Command::Open(open)]);
    chain::coins(&c).unwrap();
    let available = chain::coins(&c)
        .unwrap()
        .into_iter()
        .filter(|(_, x)| x.output.owner == a.public_key && x.spendable_height <= c.height())
        .collect::<Vec<_>>();
    assert!(available.len() >= 3);
    let reserve = |p: rld_pow::OutPoint| {
        let intent = rld_value_successor::ChallengeFeeReserveIntent {
            chain_id: c.chain_id(),
            channel,
            input: p,
            owner: a.public_key.clone(),
        };
        rld_value_successor::ChallengeFeeReserve {
            owner_signature: sign_bytes(&a.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
            intent,
        }
    };
    let fee_for = |action, state: &SignedState, input: rld_pow::OutPoint, amount: u128| {
        let intent = rld_value_successor::ActionFeeIntent {
            chain_id: c.chain_id(),
            action,
            channel,
            signed_state: rld_value_successor::signed_state_hash(state).unwrap(),
            input,
            owner: a.public_key.clone(),
            fee: Amount(1),
            change: Amount(amount - 1),
            valid_through_height: 120,
        };
        rld_value_successor::ActionFee {
            owner_signature: sign_bytes(&a.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
            intent,
        }
    };
    let close = Command::Close {
        channel,
        state: initial.clone(),
        fee: fee_for(
            rld_value_successor::DisputeAction::Close,
            &initial,
            available[0].0.clone(),
            available[0].1.output.amount.0,
        ),
    };
    let challenge = Command::Challenge {
        channel,
        state: latest.clone(),
        fee: fee_for(
            rld_value_successor::DisputeAction::Challenge,
            &latest,
            available[1].0.clone(),
            available[1].1.output.amount.0,
        ),
    };
    let commands = vec![
        Command::ReserveChallengeFee(reserve(available[1].0.clone())),
        Command::ReserveChallengeFee(reserve(available[2].0.clone())),
        close,
    ];
    mine(&mut c, &a.public_key, commands);
    chain::coins(&c).unwrap();
    let deadline = c.height() + rld_fast_payments::CONTEST_BLOCKS;
    mine(&mut c, &a.public_key, vec![challenge]);
    chain::coins(&c).unwrap();
    assert!(c
        .template(
            a.public_key.clone(),
            1_000_000 + 108 * 600,
            vec![Command::Finalize { channel }]
        )
        .is_err());
    while c.height() < deadline {
        mine(&mut c, &a.public_key, vec![]);
    }
    mine(&mut c, &a.public_key, vec![Command::Finalize { channel }]);
    let coins = chain::coins(&c).unwrap();
    assert!(matches!(
        c.state().escrow(channel).unwrap().phase,
        rld_fast_payments::Phase::Settled
    ));
    assert_eq!(
        coins
            .values()
            .filter(|x| x.output.owner == b.public_key)
            .map(|x| x.output.amount.0)
            .sum::<u128>(),
        chain::UNIT / 10
    );
    assert!(c.state().reserved_challenge_fee(&available[2].0).is_none());
    let (input, coin) = coins
        .into_iter()
        .find(|(_, x)| x.output.owner == b.public_key)
        .unwrap();
    let intent = rld_cross_region::value::ExportIntent {
        source_chain_id: c.chain_id(),
        destination_chain_id: Hash([9; 32]),
        input,
        owner: b.public_key.clone(),
        recipient: a.public_key.clone(),
        amount: Amount(chain::UNIT / 100),
        source_fee: Amount(1),
        destination_fee: Amount(1),
        change: Amount(coin.output.amount.0 - chain::UNIT / 100 - 1),
        valid_through_height: c.height() + 10,
    };
    let export = rld_cross_region::value::ExportCommand {
        owner_signature: sign_bytes(&b.secret_key, &intent.signing_bytes().unwrap()).unwrap(),
        intent,
    };
    mine(&mut c, &a.public_key, vec![Command::Export(export)]);
    chain::coins(&c).unwrap();
    assert_eq!(c.state().totals().unwrap().2 .0, chain::UNIT / 100);
}
#[test]
fn local_files_preserve_atomic_data_and_exclude_symlinks() {
    let root = std::env::temp_dir().join(format!("earth-wallet-test-{}", random()));
    files::directory(&root).unwrap();
    let path = root.join("wallet.json");
    files::atomic(&path, b"old").unwrap();
    files::atomic(&path, b"new").unwrap();
    assert_eq!(files::read(&path, 3).unwrap(), b"new");
    assert!(files::read(&path, 2).is_err());
    let link = root.join("linked");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(files::read(&link, 100).is_err());
    let lock = files::lock(&root.join("wallet.lock")).unwrap();
    assert!(files::lock(&root.join("wallet.lock")).is_err());
    drop(lock);
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn constant_time_token_check_rejects_wrong_lengths_and_bytes() {
    let token = random();
    assert!(same(&token, &token));
    assert!(!same(&token, ""));
    assert!(!same(&token, &"00".repeat(32)));
}

#[test]
fn browser_auth_rejects_rebinding_cross_site_and_missing_capability() {
    let origin = "http://127.0.0.1:48340";
    let token = random();
    let mut h = HeaderMap::new();
    h.insert(header::HOST, "127.0.0.1:48340".parse().unwrap());
    assert!(auth(origin, &token, &h).is_err());
    h.insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    assert!(auth(origin, &token, &h).is_ok());
    h.insert(header::ORIGIN, origin.parse().unwrap());
    assert!(auth(origin, &token, &h).is_ok());
    h.insert(header::ORIGIN, "https://evil.invalid".parse().unwrap());
    assert!(auth(origin, &token, &h).is_err());
    h.remove(header::ORIGIN);
    h.insert(header::HOST, "evil.invalid:48340".parse().unwrap());
    assert!(auth(origin, &token, &h).is_err());
}
#[test]
fn invalid_empty_wallet_journal_state_is_rejected() {
    assert!(validate_saved(&Saved::default()).is_ok());
    assert!(validate_saved(&Saved {
        backup_verified: true,
        ..Saved::default()
    })
    .is_err());
}

fn io_wallet(node: &str) -> (Wallet, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("earth-wallet-io-{}", random()));
    files::directory(&root).unwrap();
    let replay = chain::fixture(&root, node);
    let lock = files::lock(&root.join("wallet.lock")).unwrap();
    (
        Wallet {
            saved: Saved {
                chain_id: replay.store.chain().chain_id().to_hex(),
                ..Saved::default()
            },
            replay,
            destination: None,
            path: root.join("wallet.json"),
            secret: Some(Zeroizing::new("disposable-fixture-secret".into())),
            unlocked_until: u64::MAX,
            draft: None,
            write_failed: false,
            product_draft: None,
            _lock: lock,
        },
        root,
    )
}
#[test]
fn disk_failure_stops_signing_and_preserves_memory_until_restart() {
    let (mut w, root) = io_wallet("http://127.0.0.1:1");
    w.persist().unwrap();
    let before = files::read(&w.path, 4096).unwrap();
    std::fs::create_dir(w.path.with_extension("pending")).unwrap();
    w.saved.backup_verified = true;
    assert!(w.persist().is_err());
    assert!(w.write_failed);
    assert!(w.secret.is_none());
    assert!(w.saved.backup_verified);
    assert_eq!(files::read(&w.path, 4096).unwrap(), before);
    std::fs::remove_dir(w.path.with_extension("pending")).unwrap();
    assert!(w.persist().is_err());
    drop(w);
    std::fs::remove_dir_all(root).unwrap();
}
fn restart_wallet(w: Wallet) -> Wallet {
    let root = w.path.parent().unwrap().to_owned();
    drop(w);
    let saved = serde_json::from_slice(
        &files::read(&root.join("wallet.json"), snapshot::MAX as u64).unwrap(),
    )
    .unwrap();
    validate_saved(&saved).unwrap();
    Wallet {
        saved,
        replay: chain::fixture(&root, "http://127.0.0.1:1"),
        destination: None,
        path: root.join("wallet.json"),
        secret: None,
        unlocked_until: 0,
        draft: None,
        product_draft: None,
        write_failed: false,
        _lock: files::lock(&root.join("wallet.lock")).unwrap(),
    }
}
#[tokio::test]
async fn every_atomic_write_boundary_recovers_only_complete_records() {
    use files::WriteBoundary::*;
    for boundary in [
        Created,
        PartialWrite,
        Written,
        FileSynced,
        Renamed,
        DirectorySynced,
    ] {
        let (mut w, root) = io_wallet("http://127.0.0.1:1");
        w.saved.external_public = Some(generate_identity().public_key);
        w.persist().unwrap();
        let before = files::read(&w.path, snapshot::MAX as u64).unwrap();
        w.saved.backup_verified = true;
        let after = serde_json::to_vec(&w.saved).unwrap();
        files::fail_next_atomic(&w.path, boundary);
        assert!(w.persist().is_err(), "{boundary:?}");
        assert!(w.write_failed && w.secret.is_none());
        assert!(w
            .action(request(
                json!({"action":"unlock","password":"unused-passphrase"})
            ))
            .await
            .is_err());
        assert!(w
            .action(request(json!({"action":"product_prepare","kind":"offer"})))
            .await
            .is_err());
        let renamed = matches!(boundary, Renamed | DirectorySynced);
        assert_eq!(
            files::read(&w.path, snapshot::MAX as u64).unwrap(),
            if renamed { after } else { before }
        );
        let mut recovered = restart_wallet(w);
        assert_eq!(recovered.saved.backup_verified, renamed);
        recovered.persist().unwrap();
        assert!(!recovered.path.with_extension("pending").exists());
        drop(recovered);
        std::fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn capacity_failure_also_locks_unsaved_decisions() {
    for oversized_bytes in [false, true] {
        let (mut w, root) = io_wallet("http://127.0.0.1:1");
        w.persist().unwrap();
        let before = files::read(&w.path, snapshot::MAX as u64).unwrap();
        if oversized_bytes {
            w.saved.external_public = Some("x".repeat(snapshot::MAX));
        } else {
            w.saved.journal = vec![
                chain::Journal {
                    command: Command::Finalize {
                        channel: Hash([9; 32])
                    },
                    created_at: 1,
                };
                10001
            ];
        }
        assert!(w.persist().is_err());
        assert!(w.write_failed && w.secret.is_none());
        assert_eq!(files::read(&w.path, snapshot::MAX as u64).unwrap(), before);
        assert!(w.persist().is_err());
        let recovered = restart_wallet(w);
        assert!(recovered.saved.owner().is_none() && recovered.saved.journal.is_empty());
        drop(recovered);
        std::fs::remove_dir_all(root).unwrap();
    }
}
#[tokio::test]
async fn ambiguous_delivery_retains_the_exact_journal() {
    use std::io::{Read, Write};
    for case in ["accepted", "truncated", "wrong-id", "rejected"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let command = Command::Finalize {
            channel: Hash([9; 32]),
        };
        let id = command_id(&command).unwrap().to_hex();
        let response=json!({"status":"ADOPTED_EARTH_SUCCESSOR_V1","command":if case=="wrong-id"{"00".repeat(32)}else{id},"confirmed":false}).to_string();
        let len = response.len() + if case == "truncated" { 10 } else { 0 };
        let code = if case == "rejected" {
            "503 Service Unavailable"
        } else {
            "200 OK"
        };
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut b = [0u8; 8192];
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = stream.read(&mut b).unwrap();
            write!(
                stream,
                "HTTP/1.1 {code}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{response}"
            )
            .unwrap();
        });
        let (mut w, root) = io_wallet(&origin);
        w.saved.journal.push(chain::Journal {
            command: command.clone(),
            created_at: 0,
        });
        w.persist().unwrap();
        let before = files::read(&w.path, 4096).unwrap();
        let result = w.submit(command.clone()).await.unwrap();
        assert_eq!(
            result["delivery"],
            if case == "accepted" {
                "accepted"
            } else {
                "unknown"
            },
            "{case}"
        );
        assert_eq!(
            serde_json::to_vec(&w.saved.journal[0].command).unwrap(),
            serde_json::to_vec(&command).unwrap()
        );
        assert_eq!(files::read(&w.path, 4096).unwrap(), before);
        server.join().unwrap();
        drop(w);
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub fn fixture_validators() -> &'static Vec<rld_core::Identity> {
    static KEYS: std::sync::OnceLock<Vec<rld_core::Identity>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let mut k = (0..4).map(|_| generate_identity()).collect::<Vec<_>>();
        k.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        k
    })
}
fn request(value: Value) -> Request {
    serde_json::from_value(value).unwrap()
}
async fn create_fixture(w: &mut Wallet, password: &str) {
    w.action(request(json!({"action":"create","password":password})))
        .await
        .unwrap();
    let backup = w.saved.vault.as_ref().unwrap().clone();
    w.action(request(
        json!({"action":"verify_backup","password":password,"backup":backup}),
    ))
    .await
    .unwrap();
    w.action(request(json!({"action":"unlock","password":password})))
        .await
        .unwrap();
}
fn store_mine(w: &mut Wallet, miner: &str, commands: Vec<Command>) {
    let c = w.replay.store.chain();
    let time = 1_000_000 + (c.height() as u64 + 1) * 600;
    let mut b = c.template(miner.into(), time, commands).unwrap();
    while !mine_batch(&mut b, 10000).unwrap() {}
    w.replay.store.accept(b, time).unwrap();
}
fn sync_wallet(from: &Wallet, to: &mut Wallet) {
    for block in from.replay.store.chain().best_blocks().unwrap() {
        to.replay
            .store
            .accept(block.clone(), now().unwrap())
            .unwrap();
    }
    if let Some(cert) = from.replay.store.finality() {
        to.replay.store.install_finality(cert.clone()).unwrap();
    }
}
fn finalize_fixture(w: &mut Wallet) {
    use rld_value_successor::chain::finality::{FinalityCertificate, FinalityStatement};
    let c = w.replay.store.chain();
    let h = c.height() - 11;
    let block = c.selected_block_id(h).unwrap();
    let previous = w.replay.store.finality().map(|x| x.statement.id().unwrap());
    let statement = FinalityStatement::from_chain(c, Hash([21; 32]), block, previous).unwrap();
    let approvals = fixture_validators()
        .iter()
        .map(|k| rld_pow::transition::Approval {
            public_key: k.public_key.clone(),
            signature: sign_bytes(&k.secret_key, &statement.signing_bytes().unwrap()).unwrap(),
        })
        .collect();
    w.replay
        .store
        .install_finality(FinalityCertificate {
            statement,
            approvals,
        })
        .unwrap();
}
async fn prepare_confirm(w: &mut Wallet, mut v: Value) -> Result<Value> {
    v["action"] = json!("product_prepare");
    let p = w.action(request(v)).await?;
    w.action(request(
        json!({"action":"product_confirm","draft":p["draft"]}),
    ))
    .await
}
#[tokio::test]
async fn complete_snapshot_preserves_signed_pending_and_retirement() {
    let password = "complete-snapshot-test-passphrase";
    let (mut w, root) = io_wallet("http://127.0.0.1:1");
    w.secret = None;
    create_fixture(&mut w, password).await;
    let owner = w.saved.owner().unwrap().to_owned();
    let peer = generate_identity().public_key;
    for _ in 0..103 {
        store_mine(&mut w, &owner, vec![]);
    }
    let tx = prepare_confirm(
        &mut w,
        json!({"kind":"transfer","to":peer,"amount":"0.01","fee":"0.000001"}),
    )
    .await
    .unwrap();
    assert_eq!(tx["delivery"], "unknown");
    let original = serde_json::to_vec(&w.saved.journal).unwrap();
    let exported = w
        .action(request(json!({"action":"full_backup","password":password})))
        .await
        .unwrap();
    let snapshot: snapshot::Snapshot =
        serde_json::from_value(exported["snapshot"].clone()).unwrap();
    assert!(snapshot
        .open("wrong-snapshot-passphrase", &w.saved.chain_id)
        .is_err());
    assert!(snapshot.open(password, CHAIN).is_err());
    assert_eq!(
        serde_json::to_vec(&snapshot.open(password, &w.saved.chain_id).unwrap().journal).unwrap(),
        original
    );
    let verified = w
        .action(request(
            json!({"action":"verify_full","password":password,"snapshot":snapshot}),
        ))
        .await
        .unwrap();
    assert_eq!(verified["ok"], true);
    let retired = w
        .action(request(json!({"action":"handoff","password":password})))
        .await
        .unwrap();
    assert!(w.saved.retired && w.secret.is_none());
    assert!(w
        .action(request(json!({"action":"unlock","password":password})))
        .await
        .is_err());
    let transferred: snapshot::Snapshot =
        serde_json::from_value(retired["snapshot"].clone()).unwrap();
    let restored = transferred.open(password, &w.saved.chain_id).unwrap();
    assert!(!restored.retired);
    assert_eq!(serde_json::to_vec(&restored.journal).unwrap(), original);
    assert!(!chain::reserved(w.replay.store.chain(), &restored.journal)
        .unwrap()
        .is_empty());
    let mut bad = retired["snapshot"].clone();
    bad["public_key"] = json!(generate_identity().public_key);
    assert!(serde_json::from_value::<snapshot::Snapshot>(bad)
        .unwrap()
        .open(password, &w.saved.chain_id)
        .is_err());
    drop(w);
    std::fs::remove_dir_all(root).unwrap();
}
#[tokio::test]
async fn external_signature_is_bound_to_exact_review_and_tip() {
    let (mut w, root) = io_wallet("http://127.0.0.1:1");
    w.secret = None;
    let k = generate_identity();
    let peer = generate_identity();
    w.action(request(
        json!({"action":"external_wallet","to":k.public_key}),
    ))
    .await
    .unwrap();
    w.saved.backup_verified = true;
    for _ in 0..102 {
        store_mine(&mut w, &k.public_key, vec![]);
    }
    let p=w.action(request(json!({"action":"product_prepare","kind":"transfer","to":peer.public_key,"amount":"0.01","fee":"0.000001"}))).await.unwrap();
    let bytes = hex::decode(p["signing_request"]["message_hex"].as_str().unwrap()).unwrap();
    let wrong = sign_bytes(&peer.secret_key, &bytes).unwrap();
    assert!(w
        .action(request(
            json!({"action":"product_confirm","draft":p["draft"],"signature":wrong})
        ))
        .await
        .is_err());
    assert!(w.saved.journal.is_empty());
    let p=w.action(request(json!({"action":"product_prepare","kind":"transfer","to":peer.public_key,"amount":"0.01","fee":"0.000001"}))).await.unwrap();
    let bytes = hex::decode(p["signing_request"]["message_hex"].as_str().unwrap()).unwrap();
    let sig = sign_bytes(&k.secret_key, &bytes).unwrap();
    store_mine(&mut w, &k.public_key, vec![]);
    assert!(w
        .action(request(
            json!({"action":"product_confirm","draft":p["draft"],"signature":sig})
        ))
        .await
        .is_err());
    let p=w.action(request(json!({"action":"product_prepare","kind":"transfer","to":peer.public_key,"amount":"0.01","fee":"0.000001"}))).await.unwrap();
    let bytes = hex::decode(p["signing_request"]["message_hex"].as_str().unwrap()).unwrap();
    let sig = sign_bytes(&k.secret_key, &bytes).unwrap();
    assert_eq!(
        w.action(request(
            json!({"action":"product_confirm","draft":p["draft"],"signature":sig})
        ))
        .await
        .unwrap()["delivery"],
        "unknown"
    );
    validate_saved(&w.saved).unwrap();
    assert_eq!(w.saved.journal.len(), 1);
    drop(w);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn wallet_channel_guard_failure_exact_retry_and_restart() {
    wallet_channel_scenario(1).await;
}
#[tokio::test]
async fn wallet_sustained_1000_payments_with_durable_restarts() {
    wallet_channel_scenario(1000).await;
}
async fn wallet_channel_scenario(payments: usize) {
    use rld_value_successor::watchtower::{storage::WatchStore, WatchAck, WatchPackage};
    let password = "channel-flow-test-passphrase";
    let (mut a, ra) = io_wallet("http://127.0.0.1:1");
    let (mut b, rb) = io_wallet("http://127.0.0.1:1");
    a.secret = None;
    b.secret = None;
    create_fixture(&mut a, password).await;
    create_fixture(&mut b, password).await;
    let pa = a.saved.owner().unwrap().to_owned();
    let pb = b.saved.owner().unwrap().to_owned();
    for n in 0..105 {
        store_mine(&mut a, if n % 2 == 0 { &pa } else { &pb }, vec![]);
    }
    sync_wallet(&a, &mut b);
    let invite = prepare_confirm(
        &mut a,
        json!({"kind":"open","peer":pb,"amount":"0.1","fee":"0.000001","close_fee":"0.000001"}),
    )
    .await
    .unwrap()["packet"]
        .clone();
    validate_saved(&a.saved).unwrap();
    assert!(!product::reserved_inputs(&a.saved.products, a.replay.store.chain()).is_empty());
    let accepted = prepare_confirm(&mut b, json!({"kind":"accept","packet":invite}))
        .await
        .unwrap()["packet"]
        .clone();
    validate_saved(&b.saved).unwrap();
    prepare_confirm(&mut a, json!({"kind":"fund","packet":accepted}))
        .await
        .unwrap();
    let open = a.saved.journal.last().unwrap().command.clone();
    store_mine(&mut a, &pa, vec![open]);
    store_mine(&mut a, &pa, vec![]);
    sync_wallet(&a, &mut b);
    let channel = b.saved.products.channels[0].funding.id().unwrap();
    prepare_confirm(
        &mut b,
        json!({"kind":"reserve","channel":channel,"fee":"0.000001"}),
    )
    .await
    .unwrap();
    let reserve = b.saved.journal.last().unwrap().command.clone();
    let input = if let Command::ReserveChallengeFee(r) = &reserve {
        r.intent.input.clone()
    } else {
        panic!()
    };
    store_mine(&mut b, &pb, vec![reserve]);
    for _ in 0..12 {
        store_mine(&mut b, &pb, vec![]);
    }
    finalize_fixture(&mut b);
    sync_wallet(&b, &mut a);
    let identity = Arc::new(generate_identity());
    let key = identity.public_key.clone();
    let guard_root = rb.join("guard");
    let guard = Arc::new(Mutex::new(None::<WatchStore>));
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = {
        let guard = guard.clone();
        let identity = identity.clone();
        let fail = fail.clone();
        tokio::spawn(async move {
            let router = Router::new().route(
                "/v1/earth-watchtower/packages",
                post(move |Json(package): Json<WatchPackage>| {
                    let guard = guard.clone();
                    let identity = identity.clone();
                    let fail = fail.clone();
                    let root = guard_root.clone();
                    async move {
                        if fail.load(std::sync::atomic::Ordering::SeqCst) {
                            return StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        let mut g = guard.lock().await;
                        if g.is_none() {
                            *g = Some(WatchStore::open(&root, Some(package.clone())).unwrap());
                        }
                        g.as_mut().unwrap().observe(package.clone()).unwrap();
                        Json(
                            WatchAck::sign_saved_for_mode(
                                &package,
                                &identity.public_key,
                                &identity.secret_key,
                                true,
                            )
                            .unwrap(),
                        )
                        .into_response()
                    }
                }),
            );
            axum::serve(listener, router).await.unwrap();
        })
    };
    let protection=prepare_confirm(&mut b,json!({"kind":"protect","channel":channel,"watcher":key,"watch_url":url,"input":input,"fee":"0.000001"})).await.unwrap()["packet"].clone();
    a.action(request(
        json!({"action":"product_import_protection","packet":protection}),
    ))
    .await
    .unwrap();
    let offer = prepare_confirm(
        &mut a,
        json!({"kind":"offer","channel":channel,"amount":"0.01"}),
    )
    .await
    .unwrap()["packet"]
        .clone();
    assert!(prepare_confirm(
        &mut a,
        json!({"kind":"offer","channel":channel,"amount":"0.01"})
    )
    .await
    .is_err());
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(prepare_confirm(
        &mut b,
        json!({"kind":"receive","channel":channel,"packet":offer})
    )
    .await
    .is_err());
    assert!(b.saved.products.channels[0].pending_receive.is_some());
    validate_saved(&b.saved).unwrap();
    let original = files::read(&b.path, snapshot::MAX as u64).unwrap();
    let oldpackage = b.saved.products.channels[0].protection.clone().unwrap();
    drop(b);
    let replay = chain::fixture(&rb, "http://127.0.0.1:1");
    let lock = files::lock(&rb.join("wallet.lock")).unwrap();
    let mut b = Wallet {
        saved: serde_json::from_slice(&original).unwrap(),
        replay,
        destination: None,
        path: rb.join("wallet.json"),
        secret: None,
        unlocked_until: 0,
        draft: None,
        product_draft: None,
        write_failed: false,
        _lock: lock,
    };
    validate_saved(&b.saved).unwrap();
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let receipt = b
        .action(request(
            json!({"action":"product_retry_watch","channel":channel}),
        ))
        .await
        .unwrap()["packet"]
        .clone();
    assert_eq!(
        b.saved.products.channels[0].protection.as_ref().unwrap(),
        &oldpackage
    );
    a.action(request(
        json!({"action":"product_import_receipt","packet":receipt}),
    ))
    .await
    .unwrap();
    let before = serde_json::to_vec(&a.saved).unwrap();
    a.action(request(
        json!({"action":"product_import_receipt","packet":receipt}),
    ))
    .await
    .unwrap();
    assert_eq!(serde_json::to_vec(&a.saved).unwrap(), before);
    validate_saved(&a.saved).unwrap();
    validate_saved(&b.saved).unwrap();
    assert!(a.saved.products.channels[0].pending_offer.is_none());
    assert_eq!(
        b.saved.products.channels[0].latest.state.balance_b.0,
        chain::UNIT / 100
    );
    b.action(request(json!({"action":"unlock","password":password})))
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut latencies = Vec::new();
    let mut restarts = 0;
    for sequence in 2..=payments {
        let payment_started = std::time::Instant::now();
        let offer = prepare_confirm(
            &mut a,
            json!({"kind":"offer","channel":channel,"amount":"0.00001"}),
        )
        .await
        .unwrap()["packet"]
            .clone();
        let receipt = if matches!(sequence, 250 | 500) {
            let boundary = if sequence == 250 {
                files::WriteBoundary::FileSynced
            } else {
                files::WriteBoundary::Renamed
            };
            files::fail_next_atomic(&b.path, boundary);
            assert!(prepare_confirm(
                &mut b,
                json!({"kind":"receive","channel":channel,"packet":offer})
            )
            .await
            .is_err());
            assert!(b.write_failed && b.secret.is_none());
            // The watcher must not learn a decision before the wallet's durable
            // save completes, including an ambiguous failure after rename.
            assert_eq!(
                guard
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .latest()
                    .state
                    .state
                    .sequence,
                sequence as u64 - 1
            );
            b = restart_wallet(b);
            let result = if sequence == 250 {
                assert!(b.saved.products.channels[0].pending_receive.is_none());
                b.action(request(json!({"action":"unlock","password":password})))
                    .await
                    .unwrap();
                prepare_confirm(
                    &mut b,
                    json!({"kind":"receive","channel":channel,"packet":offer}),
                )
                .await
                .unwrap()
            } else {
                assert!(b.saved.products.channels[0].pending_receive.is_some());
                b.action(request(
                    json!({"action":"product_retry_watch","channel":channel}),
                ))
                .await
                .unwrap()
            };
            b.action(request(json!({"action":"unlock","password":password})))
                .await
                .unwrap();
            result["packet"].clone()
        } else {
            prepare_confirm(
                &mut b,
                json!({"kind":"receive","channel":channel,"packet":offer}),
            )
            .await
            .unwrap()["packet"]
                .clone()
        };
        a.action(request(
            json!({"action":"product_import_receipt","packet":receipt}),
        ))
        .await
        .unwrap();
        latencies.push(payment_started.elapsed().as_micros());
        assert_eq!(
            a.saved.products.channels[0].latest,
            b.saved.products.channels[0].latest
        );
        assert_eq!(
            a.saved.products.channels[0].latest.state.sequence,
            sequence as u64
        );
        if sequence % 100 == 0 {
            let before_a = serde_json::to_vec(&a.saved).unwrap();
            let before_b = serde_json::to_vec(&b.saved).unwrap();
            a = restart_wallet(a);
            b = restart_wallet(b);
            assert_eq!(serde_json::to_vec(&a.saved).unwrap(), before_a);
            assert_eq!(serde_json::to_vec(&b.saved).unwrap(), before_b);
            *guard.lock().await = None;
            a.action(request(json!({"action":"unlock","password":password})))
                .await
                .unwrap();
            b.action(request(json!({"action":"unlock","password":password})))
                .await
                .unwrap();
            restarts += 1;
        }
    }
    validate_saved(&a.saved).unwrap();
    validate_saved(&b.saved).unwrap();
    assert_eq!(a.saved.products.channels[0].receipts.len(), payments);
    assert_eq!(b.saved.products.channels[0].receipts.len(), payments);
    if restarts > 0 {
        b.action(request(
            json!({"action":"product_retry_watch","channel":channel}),
        ))
        .await
        .unwrap();
        assert!(guard.lock().await.is_some());
    }
    assert_eq!(
        b.saved.products.channels[0].latest.state.balance_b.0,
        chain::UNIT / 100 + (payments as u128 - 1) * chain::UNIT / 100000
    );
    let receiver_backup = snapshot::Snapshot::seal(&b.saved, password).unwrap();
    assert_eq!(
        serde_json::to_vec(&receiver_backup.open(password, &b.saved.chain_id).unwrap()).unwrap(),
        serde_json::to_vec(&b.saved).unwrap()
    );
    if !latencies.is_empty() {
        latencies.sort_unstable();
        println!(
            "RLD-WALLET-STRESS {}",
            json!({
                "scope":"isolated local wallet API + actual loopback HTTP watcher + durable files; not production or independent operators",
                "payments":payments,"measured_payments":latencies.len(),"payer_receiver_watcher_restart_cycles":restarts,
                "total_millis_including_restarts_and_backup":started.elapsed().as_millis(),
                "payment_p95_micros":latencies[(latencies.len()*95).div_ceil(100)-1],
                "payer_wallet_bytes":std::fs::metadata(&a.path).unwrap().len(),
                "receiver_wallet_bytes":std::fs::metadata(&b.path).unwrap().len(),
            "initial_watcher_failure_exact_locked_restart_retry":true
            ,"receiver_atomic_faults_before_watcher_delivery":if payments >= 500 {2} else {0}
            })
        );
    }
    b.secret = None;
    let stale = a.saved.products.channels[0].initial.clone();
    let (input, coin) = chain::coins(a.replay.store.chain())
        .unwrap()
        .into_iter()
        .find(|(_, x)| {
            x.output.owner == pa && x.spendable_height <= a.replay.store.chain().height()
        })
        .unwrap();
    let intent = rld_value_successor::ActionFeeIntent {
        chain_id: a.replay.store.chain().chain_id(),
        action: rld_value_successor::DisputeAction::Close,
        channel,
        signed_state: rld_value_successor::signed_state_hash(&stale).unwrap(),
        input,
        owner: pa.clone(),
        fee: Amount(1),
        change: Amount(coin.output.amount.0 - 1),
        valid_through_height: a.replay.store.chain().height() + 12,
    };
    let signature =
        sign_bytes(a.secret.as_ref().unwrap(), &intent.signing_bytes().unwrap()).unwrap();
    let close = Command::Close {
        channel,
        state: stale,
        fee: rld_value_successor::ActionFee {
            intent,
            owner_signature: signature,
        },
    };
    store_mine(&mut a, &pa, vec![close]);
    sync_wallet(&a, &mut b);
    assert!(
        prepare_confirm(&mut a, json!({"kind":"finalize","channel":channel}))
            .await
            .is_err()
    );
    assert!(b.secret.is_none());
    prepare_confirm(
        &mut b,
        json!({"kind":"challenge","channel":channel,"fee":"0.000001"}),
    )
    .await
    .unwrap();
    let challenge = b.saved.journal.last().unwrap().command.clone();
    store_mine(&mut b, &pb, vec![challenge]);
    let rld_fast_payments::Phase::Closing { best, .. } = &b
        .replay
        .store
        .chain()
        .state()
        .escrow(channel)
        .unwrap()
        .phase
    else {
        panic!()
    };
    assert_eq!(best.state.sequence, payments as u64);
    validate_saved(&b.saved).unwrap();
    let backup = snapshot::Snapshot::seal(&a.saved, password).unwrap();
    let recovered = backup.open(password, &a.saved.chain_id).unwrap();
    assert_eq!(recovered.products.channels[0].receipts.len(), payments);
    server.abort();
    let _ = server.await;
    drop(guard);
    drop(a);
    drop(b);
    std::fs::remove_dir_all(ra).unwrap();
    std::fs::remove_dir_all(rb).unwrap();
}

/// Browser fixture is compiled only into the Rust test executable. The production
/// executable has neither this entry point nor the isolated refresh bypass.
#[tokio::test]
#[ignore = "manual browser verification against a disposable private directory"]
async fn browser_fixture_server() {
    let root = std::path::PathBuf::from(std::env::var("RLD_WALLET_BROWSER_FIXTURE_DIR").unwrap());
    assert!(!root.exists(), "fixture directory must be new");
    files::directory(&root).unwrap();
    let replay = chain::fixture(&root, "http://127.0.0.1:1");
    let chain_id = replay.store.chain().chain_id().to_hex();
    let path = root.join("wallet.json");
    let lock = files::lock(&root.join("wallet.lock")).unwrap();
    let app = App {
        wallet: Arc::new(Mutex::new(Wallet {
            saved: Saved {
                chain_id,
                ..Saved::default()
            },
            replay,
            destination: None,
            path,
            secret: None,
            unlocked_until: 0,
            draft: None,
            product_draft: None,
            write_failed: false,
            _lock: lock,
        })),
        token: random(),
        origin: "http://127.0.0.1:48491".into(),
    };
    app.wallet.lock().await.replay.refresh().await.unwrap();
    let background = app.clone();
    tokio::spawn(async move {
        loop {
            background
                .wallet
                .lock()
                .await
                .replay
                .refresh()
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    let router = Router::new()
        .route("/", get(page))
        .route("/api/status", get(status))
        .route(
            "/api",
            post(api).route_layer(axum::middleware::from_fn_with_state(
                app.clone(),
                capability,
            )),
        )
        .layer(DefaultBodyLimit::max(34 * 1024 * 1024))
        .with_state(app.clone());
    files::atomic(
        &root.join("browser-url.txt"),
        format!("{}/#{}", app.origin, app.token).as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:48491")
        .await
        .unwrap();
    println!("ISOLATED FIXTURE ONLY: {}/#{}", app.origin, app.token);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.unwrap();
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn wallet_cross_region_import_maturity_spend_and_return_proof() {
    use rld_value_successor::destination::pow::{
        self, storage::DestinationPowStore, Context as DestinationContext, SourceFinalityTrust,
    };
    let password = "cross-region-wallet-test-passphrase";
    let (mut w, root) = io_wallet("http://127.0.0.1:1");
    w.secret = None;
    create_fixture(&mut w, password).await;
    let owner = w.saved.owner().unwrap().to_owned();
    let peer = generate_identity();
    for _ in 0..103 {
        store_mine(&mut w, &owner, vec![]);
    }
    let destination_id = Hash([31; 32]);
    prepare_confirm(&mut w,json!({"kind":"export","destination":destination_id,"to":owner,"amount":"0.01","fee":"0.000001","destination_fee":"0.000001"})).await.unwrap();
    let cmd = w.saved.journal.last().unwrap().command.clone();
    let export = if let Command::Export(e) = &cmd {
        e.intent.id().unwrap()
    } else {
        panic!()
    };
    store_mine(&mut w, &owner, vec![cmd]);
    assert!(w
        .action(request(
            json!({"action":"product_export_bundle","transaction":export})
        ))
        .await
        .is_err());
    for _ in 0..12 {
        store_mine(&mut w, &owner, vec![]);
    }
    finalize_fixture(&mut w);
    let packet = w
        .action(request(
            json!({"action":"product_export_bundle","transaction":export}),
        ))
        .await
        .unwrap()["packet"]
        .clone();
    let again = w
        .action(request(
            json!({"action":"product_export_bundle","transaction":export}),
        ))
        .await
        .unwrap()["packet"]
        .clone();
    assert_eq!(packet, again);
    let source = w.replay.store.chain();
    let context = DestinationContext {
        chain_id: destination_id,
        source_policy: rld_value_successor::chain::ObservationPolicy {
            source_chain_id: source.chain_id(),
            accepted_v1_tip: source.v1_tip(),
            minimum_confirmations: 12,
            minimum_cumulative_work: rld_core::header_work(target_limit()),
        },
        started_at: 1_000_000,
        initial_target: target_limit(),
        source_finality: Some(SourceFinalityTrust {
            earth_adoption_id: Hash([21; 32]),
            validator_keys: fixture_validators()
                .iter()
                .map(|x| x.public_key.clone())
                .collect(),
        }),
        regional: None,
        migration: None,
    };
    let store =
        DestinationPowStore::open(&root.join("destination"), context, source, now().unwrap())
            .unwrap();
    w.destination = Some(destination::Replay {
        store,
        node: "http://127.0.0.1:1".into(),
        authorization: Hash([71; 32]),
        fresh: false,
        checked: 0,
        isolated_fixture: true,
    });
    prepare_confirm(&mut w, json!({"kind":"destination_import","packet":packet}))
        .await
        .unwrap();
    let import = w.saved.destination_journal[0].command.clone();
    let import_id = destination::command_id(&import).unwrap();
    fn mine_destination(w: &mut Wallet, miner: &str, commands: Vec<pow::Command>) {
        let source = w.replay.store.chain();
        let d = w.destination.as_mut().unwrap();
        let time = 1_000_000 + (d.store.chain().height() as u64 + 1) * 600;
        let mut b = d
            .store
            .template(source, miner.into(), time, commands)
            .unwrap();
        while !pow::mine_batch(&mut b, 10000).unwrap() {}
        d.store.accept(source, b, time).unwrap();
    }
    mine_destination(&mut w, &peer.public_key, vec![import.clone()]);
    assert!(
        prepare_confirm(&mut w, json!({"kind":"destination_import","packet":packet}))
            .await
            .is_err()
    );
    assert!(prepare_confirm(&mut w,json!({"kind":"destination_transfer","to":peer.public_key,"amount":"0.005","fee":"0.000001"})).await.is_err());
    for _ in 0..6 {
        mine_destination(&mut w, &peer.public_key, vec![]);
    }
    prepare_confirm(&mut w,json!({"kind":"destination_transfer","to":peer.public_key,"amount":"0.005","fee":"0.000001"})).await.unwrap();
    validate_saved(&w.saved).unwrap();
    let transfer = w.saved.destination_journal.last().unwrap().command.clone();
    assert!(!destination::reserved(
        w.destination.as_ref().unwrap().store.chain(),
        &w.saved.destination_journal
    )
    .is_empty());
    mine_destination(&mut w, &peer.public_key, vec![transfer]);
    for _ in 0..4 {
        mine_destination(&mut w, &peer.public_key, vec![]);
    }
    let returned = w
        .action(request(
            json!({"action":"product_destination_receipt","transaction":import_id}),
        ))
        .await
        .unwrap()["packet"]
        .clone();
    let mut tampered = returned.clone();
    tampered["receipt"]["state_root"] = json!(Hash([0; 32]));
    assert!(w
        .action(request(
            json!({"action":"product_return_receipt","packet":tampered})
        ))
        .await
        .is_err());
    w.action(request(
        json!({"action":"product_return_receipt","packet":returned}),
    ))
    .await
    .unwrap();
    validate_saved(&w.saved).unwrap();
    let status = w.status().unwrap();
    assert_eq!(status["destination"]["spendable"], "0.004998");
    assert_eq!(w.saved.products.returns.len(), 1);
    let full = snapshot::Snapshot::seal(&w.saved, password).unwrap();
    let restored = full.open(password, &w.saved.chain_id).unwrap();
    assert_eq!(restored.destination_journal.len(), 2);
    assert_eq!(restored.products.returns.len(), 1);
    assert!(w
        .replay
        .store
        .chain()
        .state()
        .export_record(export)
        .is_some());
    drop(w);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn split_and_consolidate_preserve_invitation_reservations() {
    let password = "split-consolidate-test-passphrase";
    let (mut w, root) = io_wallet("http://127.0.0.1:1");
    w.secret = None;
    create_fixture(&mut w, password).await;
    let owner = w.saved.owner().unwrap().to_owned();
    for _ in 0..104 {
        store_mine(&mut w, &owner, vec![]);
    }
    prepare_confirm(
        &mut w,
        json!({"kind":"split","amount":"0.000002","fee":"0.000001"}),
    )
    .await
    .unwrap();
    let split = w.saved.journal.last().unwrap().command.clone();
    store_mine(&mut w, &owner, vec![split]);
    assert!(chain::coins(w.replay.store.chain())
        .unwrap()
        .values()
        .any(|x| x.output.owner == owner && x.output.amount.0 == 2 * 10u128.pow(18)));
    let peer = generate_identity();
    prepare_confirm(&mut w,json!({"kind":"open","peer":peer.public_key,"amount":"0.01","fee":"0.000001","close_fee":"0.000001"})).await.unwrap();
    let held = product::reserved_inputs(&w.saved.products, w.replay.store.chain());
    assert_eq!(held.len(), 1);
    prepare_confirm(&mut w, json!({"kind":"consolidate","fee":"0.000001"}))
        .await
        .unwrap();
    let consolidate = w.saved.journal.last().unwrap().command.clone();
    let Command::Transfer(t) = &consolidate else {
        panic!()
    };
    assert!(t.inputs.len() > 1 && t.inputs.iter().all(|x| !held.contains(x)));
    assert_eq!(t.outputs.len(), 1);
    assert_eq!(t.outputs[0].owner, owner);
    store_mine(&mut w, &owner, vec![consolidate]);
    validate_saved(&w.saved).unwrap();
    drop(w);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn capability_rejection_precedes_large_body_read() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (w, root) = io_wallet("http://127.0.0.1:1");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = App {
        wallet: Arc::new(Mutex::new(w)),
        token: random(),
        origin: format!("http://{addr}"),
    };
    let router = Router::new()
        .route(
            "/api",
            post(api).route_layer(axum::middleware::from_fn_with_state(
                app.clone(),
                capability,
            )),
        )
        .layer(DefaultBodyLimit::max(34 * 1024 * 1024))
        .with_state(app.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    for (token, expected) in [
        ("missing".to_owned(), "HTTP/1.1 401 "),
        (app.token.clone(), "HTTP/1.1 413 "),
    ] {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(format!("POST /api HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 36000000\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        // Deliberately never send the body: auth rejection must not await it.
        let mut bytes = [0; 8192];
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&bytes[..n]).contains(expected));
    }
    assert!(app.wallet.lock().await.saved.owner().is_none());
    server.abort();
    let _ = server.await;
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}
