use super::*;

fn batch(f: &mut Fixture, count: usize, pay: bool) {
    let node = f.node();
    let mut journal = node.journal.clone();
    let mut chain = node.chain.clone();
    for _ in 0..count {
        let commands = if pay {
            let (input, coin) = chain
                .ledger
                .coins
                .iter()
                .find(|(_, c)| c.payment.owner == public(11))
                .or_else(|| chain.ledger.coins.iter().next())
                .unwrap();
            let owner = if coin.payment.owner == public(10) {
                10
            } else {
                11
            };
            let next = if owner == 10 { 11 } else { 10 };
            let intent = Intent {
                currency: node.trust.currency().unwrap(),
                region: chain.region,
                inputs: vec![*input],
                outputs: vec![Payment {
                    owner: public(next),
                    amount: coin.payment.amount,
                }],
                fee: Amount::ZERO,
                destination: None,
                remote: None,
                destination_fee: Amount::ZERO,
                valid_through: chain.height() + 32,
            };
            let signed = SignedIntent {
                approvals: vec![Approval {
                    key: public(owner),
                    signature: sig(owner, &intent.bytes().unwrap()),
                }],
                intent,
            };
            vec![Command::Spend(Box::new(signed))]
        } else {
            vec![]
        };
        let mut block = chain
            .template(commands, public(10), &node.trust, &node.evidence)
            .unwrap();
        mine(&mut block).unwrap();
        chain
            .accept(block.clone(), &node.trust, &node.evidence)
            .unwrap();
        journal.events.push(Event::Block(Box::new(block)));
    }
    node.commit(journal).unwrap();
    assert!(node.journal.events.len() < PAGE_EVENTS);
}
fn reach(f: &mut Fixture, height: u64, pay: bool) {
    while f.node().chain.height() < height {
        let remaining = (height - f.node().chain.height()) as usize;
        let room = PAGE_EVENTS - f.node().journal.events.len();
        batch(f, remaining.min(room), pay);
    }
}

#[test]
fn ordinary_store_streams_long_signed_history_and_wallet_review_from_genesis() {
    let mut f = Fixture::with_rules(crate::segmented::RULES);
    reach(&mut f, 4, false);
    f.finalize();
    for target in [256, 512, 768, 1024, 1028] {
        reach(&mut f, target, true);
        f.finalize();
    }
    let ledger = f.node().chain.ledger.clone();
    let tip = f.node().chain.tip().unwrap();
    let head = f.manifest().head().unwrap();
    assert_eq!(f.manifest().format, SEGMENTED_FORMAT);
    assert!(f.node().journal.event_prefix.len() >= 64);
    assert!(f.node().journal.events.len() < PAGE_EVENTS);
    let pin = f.pin;
    assert!(f.node().journal.replay(&public(1), pin).is_err());
    let journal = f.node().journal.clone();
    let mut events = events(Some(&f.path), &journal).unwrap();
    let mut count = 0;
    while let Some(event) = events.next() {
        event.unwrap();
        count += 1;
        assert!(events.current.len() < PAGE_EVENTS);
    }
    assert_eq!(count, 1034);
    f.close();
    f.store = Some(Store::open_pinned(&f.path, &public(1), f.pin, head).unwrap());
    assert_eq!(f.node().chain.height(), 1028);
    assert_eq!(f.node().chain.tip().unwrap(), tip);
    assert_eq!(f.node().chain.ledger, ledger);
    assert_eq!(f.node().block_at(257).unwrap().header.height, 257);
    assert_eq!(f.node().blocks().unwrap().count(), 1028);

    // The next authenticated anchor can close a full 256-block active window;
    // a bad suffix still cannot move that anchor or debit before refusal.
    let node = f.node();
    let mut cursor = Chain::new(node.chain.region, &node.trust).unwrap();
    for block in node.blocks().unwrap() {
        let block = block.unwrap();
        if block.header.height > 512 {
            break;
        }
        cursor.accept(block, &node.trust, &node.evidence).unwrap();
    }
    assert_eq!(cursor.blocks.len(), MAX_BLOCKS);
    let before = cursor.statement(&node.trust).unwrap();
    let mut tail = node.block_at(513).unwrap();
    tail.header.state = Hash::ZERO;
    mine(&mut tail).unwrap();
    assert!(cursor.accept(tail, &node.trust, &node.evidence).is_err());
    assert_eq!(cursor.statement(&node.trust).unwrap(), before);

    // Signer custody is separate. Review signing inputs against cold native
    // history spanning an exactly full 256-block certified segment.
    let dir = f.path.join("wallet-fixture");
    let owner = 10;
    let mut wallet = crate::wallet_agent::Agent::create(&dir, f.node(), public(owner)).unwrap();
    let request = crate::wallet::Request {
        owner: public(owner),
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: public(14),
            amount: Amount(10),
        }],
        remote: None,
        fee: Amount::ZERO,
        valid_for_blocks: 8,
        valid_through: None,
    };
    let key = f.path.join("owner-fixture.json");
    let raw =
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([owner;32])})).unwrap();
    private_file(&key, &raw);
    let old = wallet.journal.head().unwrap();
    let prepared = wallet.prepare(f.node(), request, old).unwrap();
    let signed = wallet
        .sign(
            f.node(),
            prepared.draft,
            &key,
            prepared.review_commitment,
            old,
        )
        .unwrap();
    assert_eq!(signed.state, "SIGNED_PENDING_INCLUSION");
    accept_mined(f.node(), signed.commands.clone()).unwrap();
    drop(wallet);
    let wallet = crate::wallet_agent::Agent::open(&dir, f.node()).unwrap();
    assert_eq!(
        wallet.view(f.node(), signed.wallet_head).unwrap().signed[0].state,
        "INCLUDED_IN_LOCAL_LEDGER"
    );
    let meta = canonical(&f.node().journal).unwrap().len();
    let (files, bytes) = archive_usage(&f.path.join("history")).unwrap();
    drop(wallet);
    let expected = f.node().chain.ledger.clone();
    let native_head = f.manifest().head().unwrap();
    f.close();
    let archive = f.path.with_extension("private-image");
    let restored = f.path.with_extension("private-restore");
    let image =
        crate::history_archive::seal(&f.path, &archive, &public(1), f.pin, native_head).unwrap();
    assert!(image
        .files
        .keys()
        .all(|name| !name.contains("wallet") && !name.contains("key")));
    crate::history_archive::restore(&archive, &restored, &public(1), f.pin, native_head).unwrap();
    let recovered = Store::open_pinned(&restored, &public(1), f.pin, native_head).unwrap();
    assert_eq!(recovered.chain.height(), 1029);
    assert_eq!(recovered.chain.ledger, expected);
    drop(recovered);
    fs::remove_dir_all(archive).unwrap();
    fs::remove_dir_all(restored).unwrap();
    f.reopen();
    println!(
        "{}",
        serde_json::json!({"format":"RLD-NATIVE-PAGED-EVENTS-STORE-SAMPLE-V1",
        "native_implementation":implementation().unwrap(),"fixture_only":true,"live_rld":false,
        "height":1029,"actual_owner_payments":1025,"sealed_event_pages":f.node().journal.event_prefix.len(),
        "retained_tail_events":f.node().journal.events.len(),"page_event_bound":PAGE_EVENTS,
        "cold_genesis_replay_equal":true,"post_history_wallet_review_and_inclusion":true,"private_fresh_target_restore_equal":true,
        "metadata_bytes":meta,"all_retained_archive_files":files,"all_retained_archive_bytes":bytes,
        "BFT_long_history_qualified":false,"full_long_history_qualified":false})
    );
}
fn private_file(path: &Path, raw: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn paged_tail_corruption_rehashed_invalid_value_and_wrong_profile_refuse() {
    let mut f = Fixture::with_rules(crate::segmented::RULES);
    reach(&mut f, 32, false);
    let journal = f.node().journal.clone();
    let m = f.manifest();
    f.close();
    let p = f.page(&m.pages[0]);
    let original = fs::read(&p).unwrap();
    fs::write(&p, b"corrupt").unwrap();
    assert!(Store::open_pinned(&f.path, &public(1), f.pin, m.head().unwrap()).is_err());
    fs::write(&p, &original).unwrap();
    let mut reordered = m.clone();
    reordered.pages.swap(0, 1);
    f.put_manifest(&reordered);
    assert!(read_journal(&f.path).is_err());
    let mut legacy = m.clone();
    legacy.format = FORMAT.into();
    f.put_manifest(&legacy);
    assert!(read_journal(&f.path).is_err());
    f.put_manifest(&m);
    // Rehashing a complete page and metadata never authenticates native value.
    let mut object: Object = decode(&fs::read(f.page(&m.pages[1])).unwrap()).unwrap();
    let Payload::Events(page) = &mut object.payload else {
        panic!()
    };
    let Event::Block(block) = page.events.last_mut().unwrap() else {
        panic!()
    };
    block.header.state = Hash::ZERO;
    mine(block).unwrap();
    let (r, raw) = reference(&object).unwrap();
    private_file(&f.page(&r), &raw);
    let mut forged = journal.clone();
    forged.event_prefix[1] = r;
    let (_, bytes) = prepare_journal(&f.path, &forged).unwrap();
    fs::write(f.path.join("journal.json"), bytes).unwrap();
    assert!(read_journal(&f.path).is_ok());
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    f.put_manifest(&m);
    f.reopen();
    assert_eq!(f.node().chain.height(), 32);
}

#[test]
fn interrupted_paged_publication_keeps_old_head_pages_and_private_residue() {
    let mut f = Fixture::with_rules(crate::segmented::RULES);
    reach(&mut f, 31, false);
    let m = f.manifest();
    let before = canonical(&m).unwrap();
    let residue = f.path.join("journal.next");
    fs::write(&residue, b"retain interrupted native publication").unwrap();
    assert!(accept_mined(f.node(), vec![]).is_err());
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), before);
    assert_eq!(
        fs::read(&residue).unwrap(),
        b"retain interrupted native publication"
    );
    assert!(f.node().template(vec![], public(10)).is_err());
    f.close();
    f.reopen();
    assert_eq!(f.node().chain.height(), 31);
    assert_eq!(f.manifest().head().unwrap(), m.head().unwrap());
    assert!(archive_usage(&f.path.join("history")).unwrap().0 > m.pages.len());
}

#[test]
fn paged_capacity_counts_all_orphans_and_refuses_without_pruning_or_head_change() {
    let mut f = Fixture::with_rules(crate::segmented::RULES);
    reach(&mut f, 16, false);
    let before = f.manifest().head().unwrap();
    let archive = f.path.join("history");
    let (mut count, _) = archive_usage(&archive).unwrap();
    for n in 0..MAX_FILES {
        if count == MAX_FILES {
            break;
        }
        let path = archive.join(format!("{:064x}.json", n));
        if !path.exists() {
            private_file(&path, b"{}");
            count += 1;
        }
    }
    assert_eq!(archive_usage(&archive).unwrap().0, MAX_FILES);
    assert!(accept_mined(f.node(), vec![])
        .unwrap_err()
        .contains("capacity"));
    assert_eq!(f.manifest().head().unwrap(), before);
    assert_eq!(archive_usage(&archive).unwrap().0, MAX_FILES);
    f.close();
    f.reopen();
    assert_eq!(f.node().chain.height(), 16);
}
