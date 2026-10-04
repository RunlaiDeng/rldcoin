use super::*;
use crate::{channel_receipt as r, channels as c};
use channel_integration::{command, funding, parties, signed_state};
use std::{fs, os::unix::fs::PermissionsExt};
fn selected(node: &mut Store, commands: Vec<Command>) {
    let mut block = node.template(commands, public(10)).unwrap();
    mine(&mut block).unwrap();
    node.accept(block).unwrap();
}
fn certify(node: &mut Store) {
    node.finalize(checkpoint(&node.chain, &node.trust)).unwrap();
}
fn setup(limit: Option<u128>) -> (PathBuf, Store, Hash, Option<Hash>) {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-channel-receipt-{}",
            rld_core::generate_identity().public_key
        ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let p = channel_integration::package(c::SEGMENTED_RULES);
    let pin = p.currency.id().unwrap();
    let region = p.admissions[0].id().unwrap();
    let mut node = Store::create(&root.join("earth"), p, region, &public(1), pin).unwrap();
    for _ in 0..3 {
        selected(&mut node, vec![]);
    }
    let open = funding(&node.chain, &node.trust);
    let Command::Channel(ref native) = open else {
        panic!()
    };
    let channel = native.action.intent.id().unwrap();
    selected(&mut node, vec![open]);
    let reserve = limit.map(|limit| top_up(&mut node, channel, limit));
    certify(&mut node);
    (root, node, channel, reserve)
}
fn top_up(node: &mut Store, channel: Hash, limit: u128) -> Hash {
    let input = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.mature <= node.chain.height() + 1
                && coin.payment.owner == public(10)
                && coin.channel_dependencies.is_empty()
        })
        .unwrap()
        .0;
    let reserve = command(
        &node.chain,
        &node.trust,
        c::Action::Reserve {
            channel,
            input,
            fee_limit: Amount(limit),
        },
        Some(10),
        &[10],
    );
    selected(node, vec![reserve]);
    input
}
fn initial(node: &Store, channel: Hash) -> c::SignedState {
    signed_state(
        &node.chain,
        &node.trust,
        channel,
        0,
        [Amount(60), Amount::ZERO],
    )
}
fn receipt(
    node: &Store,
    reserve: Hash,
    invoice: u64,
    prior: c::SignedState,
    delta: i64,
    previous: Option<Hash>,
) -> r::Receipt {
    let parties = parties();
    let payer = if delta > 0 { 0 } else { 1 };
    let recipient = 1 - payer;
    let amount = Amount(delta.unsigned_abs() as u128);
    let mut payouts = prior.statement.payouts;
    payouts[payer] = payouts[payer].checked_sub(amount).unwrap();
    payouts[recipient] = payouts[recipient].checked_add(amount).unwrap();
    let channel = prior.statement.channel;
    let next = signed_state(
        &node.chain,
        &node.trust,
        channel,
        prior.statement.sequence + 1,
        payouts,
    );
    let statement = r::Statement {
        format: r::FORMAT.into(),
        profile: c::profile_hash().unwrap(),
        expected: r::Expectation {
            currency: node.trust.currency().unwrap(),
            region: node.chain.region,
            channel,
            invoice: id("channel-invoice-fixture", &(channel, invoice)).unwrap(),
            payer: parties[payer].clone(),
            recipient: parties[recipient].clone(),
            amount,
            challenge_fee: Amount(3),
        },
        checkpoint: node.chain.finalized.unwrap(),
        reserve,
        previous_receipt: previous,
        previous_state: r::state_id(&prior).unwrap(),
        next_state: r::state_id(&next).unwrap(),
    };
    let mut result = r::Receipt {
        statement,
        prior,
        next,
        approvals: vec![],
    };
    sign_invoice(&mut result);
    result
}
fn sign_invoice(receipt: &mut r::Receipt) {
    receipt.approvals = [10, 11]
        .iter()
        .map(|seed| Approval {
            key: public(*seed),
            signature: signature(*seed, &receipt.statement.bytes().unwrap()),
        })
        .collect();
    receipt.approvals.sort_by(|a, b| a.key.cmp(&b.key));
}
fn head(root: &std::path::Path) -> Hash {
    history::manifest(&root.join("earth"))
        .unwrap()
        .head()
        .unwrap()
}
fn accept(node: &mut Store, root: &std::path::Path, receipt: r::Receipt) -> Result<r::Accepted> {
    let expected = receipt.statement.expected.clone();
    node.accept_channel_receipt(receipt, &expected, head(root))
}

#[test]
fn native_channel_receipt_missing_insufficient_immature_and_topup_follow_actual_fee_rule() {
    let (root, mut node, channel, _) = setup(None);
    let before = node.chain.ledger.clone();
    let old_head = head(&root);
    let fake = *node.chain.ledger.coins.keys().next().unwrap();
    let absent = receipt(&node, fake, 1, initial(&node, channel), 10, None);
    assert!(accept(&mut node, &root, absent).is_err());
    assert_eq!(old_head, head(&root));
    assert_eq!(before, node.chain.ledger);
    let immature = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| coin.mature > node.chain.height() + 1)
        .unwrap()
        .0;
    let invalid = command(
        &node.chain,
        &node.trust,
        c::Action::Reserve {
            channel,
            input: immature,
            fee_limit: Amount(3),
        },
        Some(10),
        &[10],
    );
    assert!(node.template(vec![invalid], public(10)).is_err());
    assert_eq!(old_head, head(&root));
    let low = top_up(&mut node, channel, 2);
    certify(&mut node);
    let too_small = receipt(&node, low, 1, initial(&node, channel), 10, None);
    let h = head(&root);
    let ledger = node.chain.ledger.clone();
    assert!(accept(&mut node, &root, too_small).is_err());
    assert_eq!(h, head(&root));
    assert_eq!(ledger, node.chain.ledger);
    let enough = top_up(&mut node, channel, 3);
    certify(&mut node);
    let proposed = receipt(&node, enough, 1, initial(&node, channel), 10, None);
    let expected = proposed.statement.expected.clone();
    let before = node.chain.ledger.clone();
    let old = head(&root);
    let accepted = node
        .accept_channel_receipt(proposed.clone(), &expected, old)
        .unwrap();
    assert!(
        !accepted.exact_retry
            && accepted.historical_funded_state
            && accepted.monetary_ledger_unchanged
    );
    assert!(!accepted.on_chain_balance_credit && !accepted.monitoring_or_inclusion_guarantee);
    assert_eq!(before, node.chain.ledger);
    assert_ne!(old, accepted.history_head);
    assert_eq!(
        node.chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .reserves
            .len(),
        2
    ); // 16 is only an upper bound.
    assert!(node
        .accept_channel_receipt(proposed.clone(), &expected, old)
        .is_err());
    let retry = accept(&mut node, &root, proposed.clone()).unwrap();
    assert!(retry.exact_retry);
    assert_eq!(accepted.history_head, retry.history_head);
    assert_eq!(proposed, retry.receipt);
    let mut bad = proposed;
    bad.approvals[0].signature = "00".into();
    let h = head(&root);
    assert!(accept(&mut node, &root, bad).is_err());
    assert_eq!(h, head(&root));
    assert_eq!(before, node.chain.ledger);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_receipt_invoice_amount_highest_state_and_complete_signatures_refuse_reuse() {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let first = receipt(&node, reserve, 1, initial(&node, channel), 10, None);
    let old = head(&root);
    let ledger = node.chain.ledger.clone();
    let mut broken_state = first.clone();
    broken_state.next.approvals[1].signature = "00".into();
    let mut broken_invoice = first.clone();
    broken_invoice.approvals[1].signature = "00".into();
    let mut zero_fee = first.clone();
    zero_fee.statement.expected.challenge_fee = Amount::ZERO;
    sign_invoice(&mut zero_fee);
    let mut amount_mismatch = first.clone();
    amount_mismatch.statement.expected.amount = Amount(11);
    sign_invoice(&mut amount_mismatch);
    let mut unknown_profile = first.clone();
    unknown_profile.statement.profile = Hash::ZERO;
    sign_invoice(&mut unknown_profile);
    let mut wrong_state = first.clone();
    wrong_state.statement.next_state = Hash::ZERO;
    sign_invoice(&mut wrong_state);
    for invalid in [
        broken_state,
        broken_invoice,
        zero_fee,
        amount_mismatch,
        unknown_profile,
        wrong_state,
    ] {
        assert!(accept(&mut node, &root, invalid).is_err());
        assert_eq!(old, head(&root));
        assert_eq!(ledger, node.chain.ledger);
    }
    let first_id = accept(&mut node, &root, first.clone()).unwrap().receipt_id;
    let reuse = receipt(&node, reserve, 2, initial(&node, channel), 10, None);
    let h = head(&root);
    assert!(accept(&mut node, &root, reuse).is_err());
    assert_eq!(h, head(&root));
    assert!(node.conflicts.is_empty());
    let duplicate_invoice = receipt(&node, reserve, 1, first.next.clone(), -5, Some(first_id));
    assert!(accept(&mut node, &root, duplicate_invoice).is_err());
    assert_eq!(h, head(&root));
    let mut missing = receipt(&node, reserve, 2, first.next.clone(), -5, None);
    assert!(accept(&mut node, &root, missing.clone()).is_err());
    assert_eq!(h, head(&root));
    missing.statement.previous_receipt = Some(first_id);
    sign_invoice(&mut missing);
    let second = accept(&mut node, &root, missing).unwrap();
    assert_eq!(second.accepted_sequence, 2);
    assert_eq!(ledger, node.chain.ledger);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_receipt_valid_equivocation_persists_incident_but_invalid_later_envelope_never_does(
) {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let first = receipt(&node, reserve, 1, initial(&node, channel), 10, None);
    let accepted = accept(&mut node, &root, first.clone()).unwrap();
    let conflict = receipt(&node, reserve, 2, initial(&node, channel), 20, None);
    let mut invalid = conflict.clone();
    invalid.approvals[0].signature = "00".into();
    let before = node.chain.ledger.clone();
    let h = head(&root);
    assert!(accept(&mut node, &root, invalid).is_err());
    assert_eq!(h, head(&root));
    assert!(node.conflicts.is_empty());
    assert!(accept(&mut node, &root, conflict).is_err());
    assert_ne!(h, head(&root));
    assert_eq!(node.chain.ledger, before);
    assert_eq!(node.conflicts.len(), 1);
    assert!(node.safety.channels.contains_key(&channel));
    let replay = accept(&mut node, &root, first.clone()).unwrap();
    assert!(replay.exact_retry);
    assert_eq!(replay.receipt, accepted.receipt);
    let next = receipt(
        &node,
        reserve,
        3,
        first.next.clone(),
        -5,
        Some(accepted.receipt_id),
    );
    assert!(accept(&mut node, &root, next).is_err());
    let latest = head(&root);
    let pin = node.trust.currency().unwrap();
    drop(node);
    let node = Store::open_pinned(&root.join("earth"), &public(1), pin, latest).unwrap();
    assert_eq!(node.chain.ledger, before);
    assert!(node.safety.channels.contains_key(&channel));
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_receipt_real_cold_highest_state_history_image_and_invalid_tail_are_atomic() {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let old = head(&root);
    let first = receipt(&node, reserve, 1, initial(&node, channel), 10, None);
    let first_id = accept(&mut node, &root, first.clone()).unwrap().receipt_id;
    let second = receipt(&node, reserve, 2, first.next.clone(), -5, Some(first_id));
    let second_id = accept(&mut node, &root, second.clone()).unwrap().receipt_id;
    let expected = head(&root);
    let before = node.chain.ledger.clone();
    let pin = node.trust.currency().unwrap();
    drop(node);
    assert!(Store::open_pinned(&root.join("earth"), &public(1), pin, old).is_err());
    let mut node = Store::open_pinned(&root.join("earth"), &public(1), pin, expected).unwrap();
    let mut stale = receipt(&node, reserve, 3, first.next.clone(), -5, Some(first_id));
    assert!(accept(&mut node, &root, stale.clone()).is_err());
    assert_eq!(expected, head(&root));
    stale = receipt(&node, reserve, 3, second.next.clone(), 1, Some(second_id));
    let third = accept(&mut node, &root, stale.clone()).unwrap();
    assert_eq!(third.accepted_sequence, 3);
    let mut bad_journal = node.journal.clone();
    let mut bad = stale;
    bad.next.approvals[0].signature = "00".into();
    bad_journal
        .events
        .push(storage::Event::ChannelReceipt(Box::new(bad)));
    let h = head(&root);
    assert!(node.commit(bad_journal).is_err());
    assert_eq!(h, head(&root));
    assert_eq!(before, node.chain.ledger);
    drop(node);
    let image = root.join("image");
    let target = root.join("restored");
    history_archive::seal(&root.join("earth"), &image, &public(1), pin, h).unwrap();
    assert!(history_archive::restore(&image, &target, &public(1), pin, old).is_err());
    assert!(!target.exists());
    history_archive::restore(&image, &target, &public(1), pin, h).unwrap();
    let restored = Store::open_pinned(&target, &public(1), pin, h).unwrap();
    assert_eq!(restored.chain.ledger, before);
    let mut receipt_count = 0;
    for event in restored.events().unwrap() {
        if matches!(event.unwrap(), storage::Event::ChannelReceipt(_)) {
            receipt_count += 1;
        }
    }
    assert_eq!(receipt_count, 3);
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_receipt_unchanged_record_capacity_cold_replays_all_two_party_states() {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let before = node.chain.ledger.clone();
    let mut prior = initial(&node, channel);
    let mut previous = None;
    let mut journal = node.journal.clone();
    for invoice in 1..=contact::MAX_CONTACTS as u64 {
        let signed = receipt(
            &node,
            reserve,
            invoice,
            prior,
            if invoice % 2 == 1 { 1 } else { -1 },
            previous,
        );
        prior = signed.next.clone();
        previous = Some(signed.id().unwrap());
        journal
            .events
            .push(storage::Event::ChannelReceipt(Box::new(signed)));
        if journal.events.len() == history::PAGE_EVENTS {
            node.commit(journal).unwrap();
            journal = node.journal.clone();
        }
    }
    node.commit(journal).unwrap();
    assert_eq!(before, node.chain.ledger);
    let h = head(&root);
    let overflow = receipt(&node, reserve, 257, prior, 1, previous);
    assert!(accept(&mut node, &root, overflow).is_err());
    assert_eq!(h, head(&root));
    assert_eq!(before, node.chain.ledger);
    let pin = node.trust.currency().unwrap();
    drop(node);
    let node = Store::open_pinned(&root.join("earth"), &public(1), pin, h).unwrap();
    let count = node
        .events()
        .unwrap()
        .filter(|e| matches!(e, Ok(storage::Event::ChannelReceipt(_))))
        .count();
    assert_eq!(count, 256);
    assert_eq!(node.chain.ledger, before);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_receipt_publication_failure_keeps_pending_residue_and_never_acknowledges() {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let proposed = receipt(&node, reserve, 1, initial(&node, channel), 10, None);
    let before = node.chain.ledger.clone();
    let old = head(&root);
    let pending = root.join("earth/journal.next");
    fs::write(&pending, b"retained failed publication").unwrap();
    assert!(accept(&mut node, &root, proposed.clone()).is_err());
    assert_eq!(before, node.chain.ledger);
    assert_eq!(old, head(&root));
    assert_eq!(fs::read(&pending).unwrap(), b"retained failed publication");
    assert!(accept(&mut node, &root, proposed).is_err());
    assert_eq!(old, head(&root));
    assert!(!node
        .events()
        .unwrap()
        .any(|event| matches!(event, Ok(storage::Event::ChannelReceipt(_)))));
    drop(node);
    assert!(history_archive::seal(
        &root.join("earth"),
        &root.join("image"),
        &public(1),
        before.channel_state.as_ref().unwrap().declaration.currency,
        old
    )
    .is_err());
    assert!(!root.join("image").exists());
    fs::remove_dir_all(root).unwrap();
}
