use super::body_witness_tests::{certified, header, replay, stream};
use super::*;
use crate::retained_pages::packed::archive::PackedArchiveCandidate;
use crate::tests::public;
use std::process::Command as Process;

#[derive(Serialize)]
struct CompletePage {
    format: String,
    scope: Scope,
    first: u64,
    previous: Option<Hash>,
    records: Vec<Record>,
}
#[derive(Serialize, Deserialize)]
struct Caller {
    bootstrap: Bootstrap,
    prefix_head: Hash,
    prefix_manifest: crate::history::Reference,
    prefix_height: u64,
    prefix_count: u64,
    prefix_finalized: Option<Hash>,
    prefix_epoch: Hash,
    prefix_root: Hash,
    tail_head: Hash,
    whole_head: Hash,
    height: u64,
    finalized: Option<Hash>,
    epoch: Hash,
    root: Hash,
    count: u64,
}
impl Caller {
    fn pins(&self) -> NativeContinuationPinsCandidate {
        let h = header_from_bootstrap(&self.bootstrap);
        let currency = self.bootstrap.currency.id().unwrap();
        NativeContinuationPinsCandidate {
            prefix: NativePrefixPinsCandidate {
                storage_head: self.prefix_head,
                manifest: self.prefix_manifest.clone(),
                latest: PackedNativeBoundaryCandidate {
                    currency,
                    region: h.region,
                    height: self.prefix_height,
                    finalized: self.prefix_finalized,
                    epoch: self.prefix_epoch,
                    ledger_root: self.prefix_root,
                    record_count: self.prefix_count,
                },
            },
            tail_head: self.tail_head,
            complete_head: self.whole_head,
            latest: PackedNativeBoundaryCandidate {
                currency,
                region: h.region,
                height: self.height,
                finalized: self.finalized,
                epoch: self.epoch,
                ledger_root: self.root,
                record_count: self.count,
            },
        }
    }
}
fn header_from_bootstrap(bootstrap: &Bootstrap) -> Header {
    Header {
        format: FORMAT.into(),
        bootstrap: bootstrap.clone(),
        region: bootstrap.admissions[0].id().unwrap(),
    }
}
fn inventory(root: &Path) -> BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)> {
    fn walk(path: &Path, out: &mut BTreeMap<PathBuf, (Hash, u64, std::time::SystemTime)>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let m = fs::symlink_metadata(&path).unwrap();
            if m.is_dir() {
                walk(&path, out)
            } else {
                out.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(&path).unwrap()).into()),
                        m.len(),
                        m.modified().unwrap(),
                    ),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}
fn fixture() -> (
    PathBuf,
    Header,
    Replay,
    Stream<Record>,
    NativePrefixPinsCandidate,
) {
    let h = header();
    let mut hot = replay(&h);
    let (root, flat) = stream(&h, &hot);
    let scope = h.scope(&hot.trust).unwrap();
    let mut head = scope.initial().unwrap();
    let mut records = vec![];
    for i in 0..16 {
        let record = Record::Certified(Box::new(certified(&hot)));
        hot.apply(&record, &flat).unwrap();
        head = crate::retained_pages::next_head(head, i, &record).unwrap();
        records.push(record);
    }
    let raw = serde_json::to_vec(&CompletePage {
        format: "RLD-NATIVE-COMPLETE-STREAM-PAGES-V1".into(),
        scope: scope.clone(),
        first: 0,
        previous: None,
        records,
    })
    .unwrap();
    let prefix = PackedArchiveCandidate::<Record>::seal_lossless_candidate(
        &root.join("prefix"),
        scope,
        head,
        [Ok(raw)],
    )
    .unwrap();
    let manifest = prefix.manifest_reference_candidate().unwrap();
    drop(prefix);
    let pins = NativePrefixPinsCandidate {
        storage_head: head,
        manifest,
        latest: PackedNativeBoundaryCandidate {
            currency: hot.trust.currency().unwrap(),
            region: h.region,
            height: 16,
            finalized: hot.chain.finalized,
            epoch: hot.chain.epoch,
            ledger_root: hot.chain.ledger.root().unwrap(),
            record_count: 16,
        },
    };
    (root, h, hot, flat, pins)
}
fn create(
    root: &Path,
    h: &Header,
    prefix: &NativePrefixPinsCandidate,
) -> (NativeContinuationCandidate, NativeContinuationPinsCandidate) {
    NativeContinuationCandidate::create(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        prefix,
    )
    .unwrap()
}
#[test]
fn actual16_plus16_native_tail_append_and_separate_cold_matches() {
    let (root, h, mut hot, flat, prefix) = fixture();
    let original = inventory(&root.join("prefix"));
    let (mut store, mut pins) = create(&root, &h, &prefix);
    for i in 0..16 {
        let next = certified(&hot);
        let record = Record::Certified(Box::new(next.clone()));
        hot.apply(&record, &flat).unwrap();
        let independent_head =
            crate::retained_pages::next_head(pins.complete_head, 16 + i, &record).unwrap();
        pins = store.append_certified(&next, &pins).unwrap();
        assert_eq!(pins.complete_head, independent_head);
        assert_eq!(pins.latest.height, 17 + i);
        assert_eq!(pins.latest.ledger_root, hot.chain.ledger.root().unwrap());
    }
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    drop(store);
    assert_eq!(inventory(&root.join("prefix")), original);
    let caller = Caller {
        bootstrap: h.bootstrap.clone(),
        prefix_head: prefix.storage_head,
        prefix_manifest: prefix.manifest,
        prefix_height: 16,
        prefix_count: 16,
        prefix_finalized: prefix.latest.finalized,
        prefix_epoch: prefix.latest.epoch,
        prefix_root: prefix.latest.ledger_root,
        tail_head: pins.tail_head,
        whole_head: pins.complete_head,
        height: 32,
        finalized: hot.chain.finalized,
        epoch: hot.chain.epoch,
        root: hot.chain.ledger.root().unwrap(),
        count: 32,
    };
    crate::keystore::private_create(
        &root.join("caller.json"),
        &serde_json::to_vec(&caller).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::continuation_tests::cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_CONTINUATION_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("continuation-native-complete height32 records32"));
    assert_eq!(inventory(&root), before);
}
#[test]
#[ignore = "separate cold process with exact caller-owned no-value fixture"]
fn cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_CONTINUATION_CHILD").unwrap());
    let caller: Caller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let pins = caller.pins();
    let store = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &caller.bootstrap,
        &public(1),
        pins.latest.currency,
        &pins,
    )
    .unwrap();
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    println!("continuation-native-complete height32 records32 full_genesis_replay=true no_ordinary_signer_adoption=true");
}
#[test]
fn wrong_pins_and_actual_bad_signature_refuse_without_any_publication() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    let next = certified(&hot);
    let before = inventory(&root);
    for choice in 0..5 {
        let mut wrong = pins.clone();
        match choice {
            0 => wrong.prefix.manifest.hash = Hash([9; 32]),
            1 => wrong.prefix.latest.ledger_root = Hash([9; 32]),
            2 => wrong.tail_head = Hash([9; 32]),
            3 => wrong.complete_head = Hash([9; 32]),
            _ => wrong.latest.finalized = Some(Hash([9; 32])),
        }
        assert!(store.inspect(&wrong).is_err());
        assert!(store.append_certified(&next, &wrong).is_err());
        assert_eq!(inventory(&root), before);
    }
    let mut bad = next.clone();
    bad.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    let signature_error = crate::conflict::CertifiedHistory::from_snapshot(&bad)
        .verify(&hot.trust)
        .unwrap_err();
    assert_eq!(
        store.append_certified(&bad, &pins).unwrap_err(),
        signature_error
    );
    assert_eq!(inventory(&root), before);
    let updated = store.append_certified(&next, &pins).unwrap();
    drop(store);
    let before = inventory(&root);
    assert!(NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        &pins
    )
    .is_err());
    assert_eq!(inventory(&root), before);
    let opened = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &h.bootstrap,
        &public(1),
        prefix.latest.currency,
        &updated,
    )
    .unwrap();
    assert_eq!(opened.inspect(&updated).unwrap(), updated.latest);
}
#[test]
fn all_tail_publication_interruptions_refuse_reopen_and_preserve_prefix() {
    for boundary in 0..3 {
        let (root, h, mut hot, flat, prefix) = fixture();
        let original = inventory(&root.join("prefix"));
        let (mut store, mut pins) = create(&root, &h, &prefix);
        for _ in 0..15 {
            let next = certified(&hot);
            hot.apply(&Record::Certified(Box::new(next.clone())), &flat)
                .unwrap();
            pins = store.append_certified(&next, &pins).unwrap();
        }
        let next = certified(&hot);
        store.interrupt_at(boundary);
        assert!(store.append_certified(&next, &pins).is_err());
        assert!(store.inspect(&pins).is_err());
        drop(store);
        let before = inventory(&root);
        assert!(NativeContinuationCandidate::open(
            &root.join("prefix"),
            &root.join("tail"),
            &h.bootstrap,
            &public(1),
            prefix.latest.currency,
            &pins
        )
        .is_err());
        assert!(NativeContinuationCandidate::create(
            &root.join("prefix"),
            &root.join("tail"),
            &h.bootstrap,
            &public(1),
            prefix.latest.currency,
            &prefix
        )
        .is_err());
        assert_eq!(inventory(&root), before);
        assert_eq!(inventory(&root.join("prefix")), original);
    }
}
#[test]
fn aggregate_prefix_orphans_cannot_hide_behind_separate_tail_capacity() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    for index in 0..crate::history::MAX_FILES - 3 {
        let hash = id("continuation-owned-orphan-capacity", &index).unwrap();
        crate::keystore::private_create(
            &root
                .join("prefix/packs")
                .join(format!("{}.pack", hash.to_hex())),
            b"",
        )
        .unwrap();
    }
    let before = inventory(&root);
    assert!(store
        .append_certified(&certified(&hot), &pins)
        .unwrap_err()
        .contains("aggregate retained capacity"));
    assert_eq!(inventory(&root), before);
}

#[test]
fn signed_qc_bad_carried_body_never_advances_process_state_or_disk() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    let next = certified(&hot);
    let mut bad = next.clone();
    bad.blocks
        .last_mut()
        .unwrap()
        .commands
        .push(Command::Import {
            snapshot: Hash([9; 32]),
            export: Hash([8; 32]),
        });
    // The real original QC authenticates the unchanged headers, not these
    // altered carried command bytes. Full Native execution must still refuse.
    crate::conflict::CertifiedHistory::from_snapshot(&bad)
        .verify(&hot.trust)
        .unwrap();
    let before = inventory(&root);
    assert!(store.append_certified(&bad, &pins).is_err());
    assert_eq!(inventory(&root), before);
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    let updated = store.append_certified(&next, &pins).unwrap();
    assert_eq!(updated.latest.height, 17);
    assert_eq!(store.inspect(&updated).unwrap(), updated.latest);
    // A complete original certificate arriving again changes record count only.
    let duplicate = store.append_certified(&next, &updated).unwrap();
    assert_eq!(duplicate.latest.height, 17);
    assert_eq!(duplicate.latest.record_count, 18);
    assert_eq!(duplicate.latest.ledger_root, updated.latest.ledger_root);
    assert_eq!(store.inspect(&duplicate).unwrap(), duplicate.latest);
}
#[test]
fn held_process_state_refuses_any_changed_complete_prefix_object() {
    let (root, h, hot, _flat, prefix) = fixture();
    let (mut store, pins) = create(&root, &h, &prefix);
    let object = fs::read_dir(root.join("prefix/packs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut raw = fs::read(&object).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    fs::write(&object, raw).unwrap();
    let before = inventory(&root);
    let next = certified(&hot);
    assert!(store
        .append_certified(&next, &pins)
        .unwrap_err()
        .contains("complete object differs"));
    assert_eq!(inventory(&root), before);
    assert!(store.inspect(&pins).is_err());
    assert_eq!(inventory(&root), before);
}

fn owner_payment(
    h: &Header,
    inputs: Vec<Hash>,
    outputs: Vec<Payment>,
    owner: u8,
    valid_through: u64,
) -> SignedIntent {
    let intent = Intent {
        currency: h.bootstrap.currency.id().unwrap(),
        region: h.region,
        inputs,
        outputs,
        fee: Amount(1),
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through,
    };
    SignedIntent {
        approvals: vec![Approval {
            key: public(owner),
            signature: crate::tests::signature(owner, &intent.bytes().unwrap()),
        }],
        intent,
    }
}
fn proposal_certificate(
    hot: &Replay,
    context: &crate::bft::Context,
    block: &Block,
) -> crate::bft::Certificate {
    use crate::bft::{Phase, Quorum, Vote};
    let mut chain = hot.chain.clone();
    crate::paged_bft::prepare_parent(&mut chain, &hot.evidence).unwrap();
    chain
        .accept(block.clone(), &hot.trust, &hot.evidence)
        .unwrap();
    let value = chain.statement(&hot.trust).unwrap().id().unwrap();
    let mut seeds = [2, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    let quorum = |phase| Quorum {
        context: context.clone(),
        round: 0,
        value,
        phase,
        votes: seeds[..3]
            .iter()
            .map(|seed| {
                let mut vote = Vote {
                    context: context.clone(),
                    round: 0,
                    value,
                    phase,
                    approval: Approval {
                        key: public(*seed),
                        signature: String::new(),
                    },
                };
                vote.approval.signature = crate::tests::signature(*seed, &vote.bytes().unwrap());
                vote
            })
            .collect(),
    };
    crate::bft::Certificate {
        prepared: quorum(Phase::Prepare),
        committed: quorum(Phase::Commit),
    }
}
fn submit_proposal(
    store: &mut NativeContinuationCandidate,
    hot: &mut Replay,
    flat: &Stream<Record>,
    commands: Vec<Command>,
    miner: u8,
    pins: &NativeContinuationPinsCandidate,
) -> NativeContinuationPinsCandidate {
    let (context, mut block) = store.template(commands, public(miner), pins).unwrap();
    mine(&mut block).unwrap();
    let certificate = proposal_certificate(hot, &context, &block);
    let snapshot = store
        .snapshot_for_certificate(&block, &certificate, pins)
        .unwrap();
    hot.apply(&Record::Certified(Box::new(snapshot.clone())), flat)
        .unwrap();
    let expected_head = crate::retained_pages::next_head(
        pins.complete_head,
        pins.latest.record_count,
        &Record::Certified(Box::new(snapshot.clone())),
    )
    .unwrap();
    let updated = store.append_certified(&snapshot, pins).unwrap();
    assert_eq!(updated.complete_head, expected_head);
    assert_eq!(updated.latest.ledger_root, hot.chain.ledger.root().unwrap());
    hot.chain.ledger.audit().unwrap();
    updated
}
#[derive(Serialize, Deserialize)]
struct PaymentCaller {
    caller: Caller,
    coins: BTreeMap<String, Vec<(Hash, Coin)>>,
}
#[test]
fn guarded_proposal_actual_owner_payment_reward_maturity_and_independent_cold() {
    let (root, h, mut hot, flat, prefix) = fixture();
    let original = inventory(&root.join("prefix"));
    let (mut store, mut pins) = create(&root, &h, &prefix);
    let mature = store
        .coins(&public(10), &pins)
        .unwrap()
        .into_iter()
        .filter(|(_, coin)| coin.mature <= 17)
        .take(3)
        .collect::<Vec<_>>();
    assert_eq!(mature.len(), 3);
    let total = mature
        .iter()
        .try_fold(Amount::ZERO, |sum, (_, coin)| {
            sum.checked_add(coin.payment.amount)
        })
        .unwrap();
    let signed = owner_payment(
        &h,
        mature.iter().map(|(id, _)| *id).collect(),
        vec![
            Payment {
                owner: public(20),
                amount: Amount(7),
            },
            Payment {
                owner: public(10),
                amount: total.checked_sub(Amount(8)).unwrap(),
            },
        ],
        10,
        24,
    );
    let before = inventory(&root);
    let mut bad = signed.clone();
    bad.approvals[0].signature = "00".repeat(64);
    assert!(store
        .template(vec![Command::Spend(Box::new(bad))], public(30), &pins)
        .is_err());
    assert_eq!(inventory(&root), before);
    let (context, mut block) = store
        .template(
            vec![Command::Spend(Box::new(signed.clone()))],
            public(30),
            &pins,
        )
        .unwrap();
    assert_eq!(context.parent_height, 16);
    assert_eq!(inventory(&root), before);
    mine(&mut block).unwrap();
    let certificate = proposal_certificate(&hot, &context, &block);
    for choice in 0..5 {
        let mut bad = certificate.clone();
        match choice {
            0 => {
                bad.committed.votes.pop();
            }
            1 => bad.committed.votes[0].approval.signature = "00".repeat(64),
            2 => bad.prepared.phase = crate::bft::Phase::Commit,
            3 => bad.committed.context.parent_state = Hash([9; 32]),
            _ => bad.committed.votes[0].approval.key = public(7),
        }
        assert!(store.snapshot_for_certificate(&block, &bad, &pins).is_err());
        assert_eq!(inventory(&root), before);
    }
    let mut altered = block.clone();
    altered.commands.clear();
    assert!(store
        .snapshot_for_certificate(&altered, &certificate, &pins)
        .is_err());
    assert_eq!(inventory(&root), before);
    let snapshot = store
        .snapshot_for_certificate(&block, &certificate, &pins)
        .unwrap();
    assert_eq!(inventory(&root), before);
    hot.apply(&Record::Certified(Box::new(snapshot.clone())), &flat)
        .unwrap();
    let old = pins.clone();
    pins = store.append_certified(&snapshot, &pins).unwrap();
    assert_eq!(pins.latest.ledger_root, hot.chain.ledger.root().unwrap());
    let before = inventory(&root);
    assert!(store.template(vec![], public(30), &old).is_err());
    assert!(store.coins(&public(20), &old).is_err());
    assert_eq!(inventory(&root), before);
    let received = store.coins(&public(20), &pins).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].1.payment.amount, Amount(7));
    assert_eq!(received[0].1.mature, 17);
    for (id, _) in &mature {
        assert!(!hot.chain.ledger.coins.contains_key(id));
    }
    let change = id("output", &(signed.intent.id().unwrap(), 1u32)).unwrap();
    assert_eq!(
        hot.chain.ledger.coins[&change].payment.amount,
        total.checked_sub(Amount(8)).unwrap()
    );
    let miner = store.coins(&public(30), &pins).unwrap();
    assert_eq!(miner.len(), 2);
    assert!(miner.iter().all(|(_, coin)| coin.mature == 19));
    assert_eq!(
        miner
            .iter()
            .try_fold(Amount::ZERO, |sum, (_, coin)| sum
                .checked_add(coin.payment.amount))
            .unwrap(),
        rld_pow::subsidy(17)
            .unwrap()
            .checked_add(Amount(1))
            .unwrap()
    );
    let immature = owner_payment(
        &h,
        miner.iter().map(|(id, _)| *id).collect(),
        vec![Payment {
            owner: public(40),
            amount: rld_pow::subsidy(17).unwrap(),
        }],
        30,
        24,
    );
    let before = inventory(&root);
    assert!(store
        .template(
            vec![Command::Spend(Box::new(immature.clone()))],
            public(50),
            &pins
        )
        .unwrap_err()
        .contains("immature input"));
    assert_eq!(inventory(&root), before);
    let onward = owner_payment(
        &h,
        vec![received[0].0],
        vec![Payment {
            owner: public(21),
            amount: Amount(6),
        }],
        20,
        24,
    );
    pins = submit_proposal(
        &mut store,
        &mut hot,
        &flat,
        vec![Command::Spend(Box::new(onward))],
        30,
        &pins,
    );
    assert!(store.coins(&public(20), &pins).unwrap().is_empty());
    assert_eq!(
        store.coins(&public(21), &pins).unwrap()[0].1.payment.amount,
        Amount(6)
    );
    pins = submit_proposal(
        &mut store,
        &mut hot,
        &flat,
        vec![Command::Spend(Box::new(immature))],
        50,
        &pins,
    );
    assert_eq!(pins.latest.height, 19);
    assert_eq!(
        store.coins(&public(40), &pins).unwrap()[0].1.payment.amount,
        rld_pow::subsidy(17).unwrap()
    );
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    hot.chain.ledger.audit().unwrap();
    let coins = [10, 20, 21, 30, 40, 50]
        .iter()
        .map(|owner| {
            let key = public(*owner);
            let got = store.coins(&key, &pins).unwrap();
            let expected = hot
                .chain
                .ledger
                .coins
                .iter()
                .filter(|(_, coin)| coin.payment.owner == key)
                .map(|(id, coin)| (*id, coin.clone()))
                .collect::<Vec<_>>();
            assert_eq!(got, expected);
            (key, expected)
        })
        .collect();
    drop(store);
    assert_eq!(inventory(&root.join("prefix")), original);
    let caller = Caller {
        bootstrap: h.bootstrap.clone(),
        prefix_head: prefix.storage_head,
        prefix_manifest: prefix.manifest,
        prefix_height: 16,
        prefix_count: 16,
        prefix_finalized: prefix.latest.finalized,
        prefix_epoch: prefix.latest.epoch,
        prefix_root: prefix.latest.ledger_root,
        tail_head: pins.tail_head,
        whole_head: pins.complete_head,
        height: 19,
        finalized: hot.chain.finalized,
        epoch: hot.chain.epoch,
        root: hot.chain.ledger.root().unwrap(),
        count: 19,
    };
    crate::keystore::private_create(
        &root.join("payment-caller.json"),
        &serde_json::to_vec(&PaymentCaller { caller, coins }).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::continuation_tests::payment_cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_CONTINUATION_PAYMENT_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("actual-native-payment-cold height19 records19"));
    assert_eq!(inventory(&root), before);
    println!("actual-native-template-payments owner10_to20=7 owner20_to21=6 mature_miner30_to40=true fee1_each=true QC3_each_phase=true reward_maturity2=true full_cold_height19=true no_ordinary_signer_adoption=true");
}
#[test]
#[ignore = "separate cold child with independently retained complete payment state"]
fn payment_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_CONTINUATION_PAYMENT_CHILD").unwrap());
    let expected: PaymentCaller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("payment-caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let pins = expected.caller.pins();
    let store = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &expected.caller.bootstrap,
        &public(1),
        pins.latest.currency,
        &pins,
    )
    .unwrap();
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    for (owner, coins) in expected.coins {
        assert_eq!(store.coins(&owner, &pins).unwrap(), coins);
    }
    println!("actual-native-payment-cold height19 records19 complete_native_balances=true");
}

#[test]
fn authenticated_genesis_prefix_first_proposal_payment_and_separate_cold() {
    let h = header();
    let mut hot = replay(&h);
    let (root, flat) = stream(&h, &hot);
    let currency = h.bootstrap.currency.id().unwrap();
    let before = inventory(&root);
    for choice in 0..5 {
        let mut bad = h.bootstrap.clone();
        let mut authority = public(1);
        let mut pin = currency;
        let mut region = h.region;
        match choice {
            0 => authority = public(7),
            1 => pin = Hash([9; 32]),
            2 => region = Hash([9; 32]),
            3 => bad.currency.signature = "00".repeat(64),
            _ => bad.admissions[0].signature = "00".repeat(64),
        }
        assert!(NativeContinuationCandidate::create_genesis_prefix(
            &root.join("refused-prefix"),
            &bad,
            &authority,
            pin,
            region,
        )
        .is_err());
        assert!(!root.join("refused-prefix").exists());
        assert_eq!(inventory(&root), before);
    }
    let prefix = NativeContinuationCandidate::create_genesis_prefix(
        &root.join("prefix"),
        &h.bootstrap,
        &public(1),
        currency,
        h.region,
    )
    .unwrap();
    assert_eq!(prefix.latest.record_count, 0);
    assert_eq!(prefix.latest.height, 0);
    assert_eq!(prefix.latest.finalized, None);
    assert_eq!(prefix.latest.ledger_root, hot.chain.ledger.root().unwrap());
    let original = inventory(&root.join("prefix"));
    assert!(NativeContinuationCandidate::create_genesis_prefix(
        &root.join("prefix"),
        &h.bootstrap,
        &public(1),
        currency,
        h.region,
    )
    .is_err());
    assert_eq!(inventory(&root.join("prefix")), original);
    let mut bad = prefix.clone();
    bad.latest.ledger_root = Hash([9; 32]);
    assert!(NativeContinuationCandidate::create(
        &root.join("prefix"),
        &root.join("refused-tail"),
        &h.bootstrap,
        &public(1),
        currency,
        &bad,
    )
    .is_err());
    assert!(!root.join("refused-tail").exists());
    let (mut store, mut pins) = create(&root, &h, &prefix);
    assert_eq!(store.inspect(&pins).unwrap(), prefix.latest);
    assert!(store.coins(&public(10), &pins).unwrap().is_empty());
    let (context, _) = store.template(vec![], public(10), &pins).unwrap();
    assert_eq!(context.parent_height, 0);
    assert_eq!(context.previous, None);
    pins = submit_proposal(&mut store, &mut hot, &flat, vec![], 10, &pins);
    assert_eq!(pins.latest.height, 1);
    let reward = store.coins(&public(10), &pins).unwrap();
    assert_eq!(reward.len(), 1);
    assert_eq!(reward[0].1.mature, 3);
    let amount = reward[0].1.payment.amount.checked_sub(Amount(1)).unwrap();
    let payment = owner_payment(
        &h,
        vec![reward[0].0],
        vec![Payment {
            owner: public(20),
            amount,
        }],
        10,
        24,
    );
    let before = inventory(&root);
    assert!(store
        .template(
            vec![Command::Spend(Box::new(payment.clone()))],
            public(30),
            &pins
        )
        .unwrap_err()
        .contains("immature input"));
    assert_eq!(inventory(&root), before);
    pins = submit_proposal(&mut store, &mut hot, &flat, vec![], 30, &pins);
    pins = submit_proposal(
        &mut store,
        &mut hot,
        &flat,
        vec![Command::Spend(Box::new(payment))],
        30,
        &pins,
    );
    assert_eq!(pins.latest.height, 3);
    assert_eq!(pins.latest.record_count, 3);
    assert!(store.coins(&public(10), &pins).unwrap().is_empty());
    let received = store.coins(&public(20), &pins).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].1.payment.amount, amount);
    assert_eq!(received[0].1.mature, 3);
    hot.chain.ledger.audit().unwrap();
    let coins = [10, 20, 30]
        .iter()
        .map(|owner| {
            let key = public(*owner);
            let expected = hot
                .chain
                .ledger
                .coins
                .iter()
                .filter(|(_, coin)| coin.payment.owner == key)
                .map(|(id, coin)| (*id, coin.clone()))
                .collect::<Vec<_>>();
            assert_eq!(store.coins(&key, &pins).unwrap(), expected);
            (key, expected)
        })
        .collect();
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    drop(store);
    assert_eq!(inventory(&root.join("prefix")), original);
    let caller = Caller {
        bootstrap: h.bootstrap.clone(),
        prefix_head: prefix.storage_head,
        prefix_manifest: prefix.manifest,
        prefix_height: 0,
        prefix_count: 0,
        prefix_finalized: None,
        prefix_epoch: prefix.latest.epoch,
        prefix_root: prefix.latest.ledger_root,
        tail_head: pins.tail_head,
        whole_head: pins.complete_head,
        height: 3,
        finalized: hot.chain.finalized,
        epoch: hot.chain.epoch,
        root: hot.chain.ledger.root().unwrap(),
        count: 3,
    };
    crate::keystore::private_create(
        &root.join("genesis-caller.json"),
        &serde_json::to_vec(&PaymentCaller { caller, coins }).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let output = Process::new(std::env::current_exe().unwrap())
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "storage::paged::continuation_tests::genesis_cold_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RLD_CONTINUATION_GENESIS_CHILD", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("actual-native-genesis-cold height3 records3"));
    assert_eq!(inventory(&root), before);
    println!("actual-native-genesis-start empty_prefix=true first_QC3=true reward_maturity2=true actual_owner_payment=true full_cold_height3=true no_ordinary_node_adoption=true");
}
#[test]
#[ignore = "separate cold child for fresh authenticated no-value genesis continuation"]
fn genesis_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_CONTINUATION_GENESIS_CHILD").unwrap());
    let expected: PaymentCaller = serde_json::from_slice(
        &crate::keystore::private_read(&root.join("genesis-caller.json"), MAX_BYTES).unwrap(),
    )
    .unwrap();
    let pins = expected.caller.pins();
    let store = NativeContinuationCandidate::open(
        &root.join("prefix"),
        &root.join("tail"),
        &expected.caller.bootstrap,
        &public(1),
        pins.latest.currency,
        &pins,
    )
    .unwrap();
    assert_eq!(store.inspect(&pins).unwrap(), pins.latest);
    for (owner, coins) in expected.coins {
        assert_eq!(store.coins(&owner, &pins).unwrap(), coins);
    }
    println!("actual-native-genesis-cold height3 records3 actual_balances_maturity=true");
}
