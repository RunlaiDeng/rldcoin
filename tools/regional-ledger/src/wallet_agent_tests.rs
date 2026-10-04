use super::*;
use crate::{wallet::Request, wallet_agent::Agent};
use std::fs;

fn request() -> Request {
    Request {
        owner: public(10),
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: public(14),
            amount: Amount(30),
        }],
        remote: None,
        fee: Amount(1),
        valid_for_blocks: 8,
        valid_through: None,
    }
}
fn key(root: &std::path::Path) -> PathBuf {
    let p = root.join("owner.json");
    fs::write(
        &p,
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}
fn step(node: &mut Store, commands: Vec<Command>) {
    let mut block = node.template(commands, public(10)).unwrap();
    mine(&mut block).unwrap();
    node.accept(block).unwrap();
}
#[test]
fn pending_reservations_survive_restart_and_exact_response_loss_retry() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    let dir = root.join("wallet");
    let mut agent = Agent::create(&dir, &node, public(10)).unwrap();
    let old = agent.journal.head().unwrap();
    let prepared = agent.prepare(&node, request(), old).unwrap();
    let input = prepared.draft.intent.inputs[0];
    let signed = agent
        .sign(
            &node,
            prepared.draft.clone(),
            &key(&root),
            prepared.review_commitment,
            old,
        )
        .unwrap();
    assert!(!signed.recovered_exact_retry);
    let next = signed.wallet_head;
    drop(agent);
    let mut agent = Agent::open(&dir, &node).unwrap();
    assert!(agent.view(&node, old).is_err());
    let view = agent.view(&node, next).unwrap();
    assert_eq!(view.reserved_owned_outputs, Amount(100));
    assert_eq!(view.available, Amount(100));
    assert!(view.ledger.pending_signed_intents_tracked);
    let retry = agent
        .sign(
            &node,
            prepared.draft,
            &root.join("key-not-needed-for-retry"),
            prepared.review_commitment,
            old,
        )
        .unwrap();
    assert_eq!(retry.commands, signed.commands);
    assert_eq!(retry.wallet_head, next);
    assert!(retry.recovered_exact_retry);
    assert_eq!(agent.journal.records.len(), 1);
    let another = agent.prepare(&node, request(), next).unwrap();
    assert!(!another.draft.intent.inputs.contains(&input));
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn inclusion_releases_only_reservation_and_never_refunds_export() {
    let f = Fixture::new();
    let (root, mut node) = stored_fixture(&f, &f.earth);
    node.finalize(
        f.evidence
            .snapshot(f.earth.finalized.unwrap())
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut agent = Agent::create(&root.join("wallet"), &node, public(10)).unwrap();
    let head = agent.journal.head().unwrap();
    let mut remote = request();
    remote.outputs.clear();
    remote.remote = Some(wallet::Remote {
        destination: f.proxima.region,
        recipient: Payment {
            owner: public(11),
            amount: Amount(99),
        },
        destination_fee: Amount(1),
    });
    let prepared = agent.prepare(&node, remote, head).unwrap();
    let signed = agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    step(&mut node, signed.commands.clone());
    let view = agent.view(&node, signed.wallet_head).unwrap();
    assert_eq!(view.reserved_owned_outputs, Amount::ZERO);
    assert_eq!(view.signed[0].state, "INCLUDED_IN_LOCAL_LEDGER");
    assert!(!view.signed[0].local_export_finalized);
    assert_eq!(view.ledger.spendable, Amount(200));
    assert_eq!(
        node.chain.ledger.exports[&signed.intent_id]
            .recipient
            .amount,
        Amount(99)
    );
    node.finalize(checkpoint(&node.chain, &node.trust)).unwrap();
    assert!(agent.view(&node, signed.wallet_head).unwrap().signed[0].local_export_finalized);
    node.observe_conflict(conflict_proof(&f)).unwrap();
    let affected = agent.view(&node, signed.wallet_head).unwrap();
    assert!(affected.local_region_quarantined);
    assert!(affected.signed[0].quarantined);
    assert!(!affected.signed[0].local_export_finalized);
    assert_eq!(affected.incident_ids.len(), 1);
    assert_eq!(
        node.chain.ledger.exports[&signed.intent_id]
            .recipient
            .amount,
        Amount(99)
    );
    let recovered = agent
        .recover(&node, signed.intent_id, signed.wallet_head)
        .unwrap();
    assert_eq!(recovered.commands, signed.commands);
    assert!(node.template(recovered.commands, public(10)).is_err());
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn only_native_expiry_frees_unincluded_inputs_not_receipt_or_wall_time() {
    let f = Fixture::new();
    let (root, mut node) = stored_fixture(&f, &f.earth);
    let mut agent = Agent::create(&root.join("wallet"), &node, public(10)).unwrap();
    let head = agent.journal.head().unwrap();
    let mut req = request();
    req.valid_for_blocks = 1;
    let prepared = agent.prepare(&node, req, head).unwrap();
    let input = prepared.draft.intent.inputs[0];
    let signed = agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    fs::write(
        root.join("untrusted-transport-receipt.json"),
        b"{\"delivered\":true}",
    )
    .unwrap();
    assert_eq!(
        agent.view(&node, signed.wallet_head).unwrap().signed[0].state,
        "SIGNED_PENDING_INCLUSION"
    );
    step(&mut node, vec![]); // Next candidate height is now strictly beyond expiry.
    assert!(node.template(signed.commands, public(10)).is_err());
    let view = agent.view(&node, signed.wallet_head).unwrap();
    assert_eq!(view.signed[0].state, "EXPIRED_BEFORE_INCLUSION");
    assert_eq!(view.reserved_owned_outputs, Amount::ZERO);
    assert_eq!(view.available, Amount(300));
    let mut req = request();
    req.inputs = Some(vec![input]);
    let prepared = agent.prepare(&node, req, signed.wallet_head).unwrap();
    assert!(prepared.draft.intent.inputs.contains(&input));
    agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            signed.wallet_head,
        )
        .unwrap();
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn separately_retained_head_rejects_old_wallet_backup() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    let dir = root.join("wallet");
    let mut agent = Agent::create(&dir, &node, public(10)).unwrap();
    let head = agent.journal.head().unwrap();
    let backup = fs::read(dir.join("wallet.json")).unwrap();
    let prepared = agent.prepare(&node, request(), head).unwrap();
    let signed = agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    drop(agent);
    fs::write(dir.join("wallet.json"), backup).unwrap();
    let agent = Agent::open(&dir, &node).unwrap();
    assert!(agent.prepare(&node, request(), signed.wallet_head).is_err());
    assert!(agent.view(&node, signed.wallet_head).is_err());
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn retained_wallet_rejects_node_backup_after_later_authorized_signing() {
    let f = Fixture::new();
    let (root, mut node) = stored_fixture(&f, &f.earth);
    let dir = root.join("wallet");
    let backup = fs::read(root.join("journal.json")).unwrap();
    let mut agent = Agent::create(&dir, &node, public(10)).unwrap();
    let head = agent.journal.head().unwrap();
    step(&mut node, vec![]);
    let prepared = agent.prepare(&node, request(), head).unwrap();
    agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    drop(agent);
    let pin = node.trust.currency().unwrap();
    drop(node);
    fs::write(root.join("journal.json"), backup).unwrap();
    let node = Store::open(&root, &public(1), pin).unwrap();
    assert!(Agent::open(&dir, &node).is_err());
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn write_failure_never_releases_signature_and_exact_interrupted_commit_recovers() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    let dir = root.join("wallet");
    let mut agent = Agent::create(&dir, &node, public(10)).unwrap();
    let head = agent.journal.head().unwrap();
    let previous = agent.journal.clone();
    let prepared = agent.prepare(&node, request(), head).unwrap();
    fs::write(dir.join("wallet.next"), b"partial").unwrap();
    assert!(agent
        .sign(
            &node,
            prepared.draft.clone(),
            &key(&root),
            prepared.review_commitment,
            head
        )
        .is_err());
    assert_eq!(agent.journal.head().unwrap(), head);
    assert!(agent.view(&node, head).is_err());
    drop(agent);
    assert!(Agent::open(&dir, &node).is_err());
    assert_eq!(fs::read(dir.join("wallet.next")).unwrap(), b"partial");
    fs::remove_file(dir.join("wallet.next")).unwrap(); // Fixture fault removed, never a normal cancellation path.
    let mut agent = Agent::open(&dir, &node).unwrap();
    let signed = agent
        .sign(
            &node,
            prepared.draft.clone(),
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    let proposed = agent.journal.clone();
    drop(agent);
    fs::write(
        dir.join("wallet.json"),
        serde_json::to_vec(&previous).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("wallet.next"),
        serde_json::to_vec(&proposed).unwrap(),
    )
    .unwrap();
    let mut agent = Agent::open(&dir, &node).unwrap();
    assert_eq!(agent.journal.head().unwrap(), signed.wallet_head);
    assert!(!dir.join("wallet.next").exists());
    let retry = agent
        .sign(
            &node,
            prepared.draft,
            &root.join("missing-key"),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    assert_eq!(retry.commands, signed.commands);
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn wallet_lock_and_corruption_fail_closed_without_overwriting_retained_commands() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    let dir = root.join("wallet");
    let mut agent = Agent::create(&dir, &node, public(10)).unwrap();
    assert!(Agent::open(&dir, &node).is_err());
    let head = agent.journal.head().unwrap();
    let prepared = agent.prepare(&node, request(), head).unwrap();
    agent
        .sign(
            &node,
            prepared.draft,
            &key(&root),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    let mut journal = agent.journal.clone();
    journal.records[0].previous_head = Hash([9; 32]);
    drop(agent);
    let bytes = serde_json::to_vec(&journal).unwrap();
    fs::write(dir.join("wallet.json"), &bytes).unwrap();
    assert!(Agent::open(&dir, &node).is_err());
    assert_eq!(fs::read(dir.join("wallet.json")).unwrap(), bytes);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_wallet_head_and_explicit_reserved_inputs_cannot_sign_again() {
    let f = Fixture::new();
    let (root, node) = stored_fixture(&f, &f.earth);
    let mut agent = Agent::create(&root.join("wallet"), &node, public(10)).unwrap();
    let old = agent.journal.head().unwrap();
    let p = agent.prepare(&node, request(), old).unwrap();
    let p2 = agent.prepare(&node, request(), old).unwrap();
    let reserved = p.draft.intent.inputs.clone();
    let signed = agent
        .sign(&node, p.draft, &key(&root), p.review_commitment, old)
        .unwrap();
    let mut altered = p2.draft;
    altered.intent.outputs[0].amount = Amount(31);
    let review = id("wallet-reviewed-draft", &altered).unwrap();
    assert!(agent
        .sign(&node, altered, &key(&root), review, old)
        .is_err());
    let mut r = request();
    r.inputs = Some(reserved);
    assert!(agent.prepare(&node, r, signed.wallet_head).is_err());
    let mut other = request();
    other.owner = public(11);
    assert!(agent.prepare(&node, other, signed.wallet_head).is_err());
    drop(agent);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

fn group_fixture(f: &Fixture) -> (PathBuf, Store, Request) {
    let (root, mut node) = stored_fixture(f, &f.earth);
    let mut funding = request();
    funding.outputs = vec![Payment {
        owner: public(11),
        amount: Amount(60),
    }];
    let draft = wallet::prepare(&node, funding).unwrap();
    let review = id("wallet-reviewed-draft", &draft).unwrap();
    let command = wallet::sign(&node, draft, &key(&root), review).unwrap();
    step(&mut node, vec![command]);
    let mut inputs = node
        .chain
        .ledger
        .coins
        .iter()
        .filter(|(_, c)| {
            c.payment
                == Payment {
                    owner: public(10),
                    amount: Amount(39),
                }
                || c.payment
                    == Payment {
                        owner: public(11),
                        amount: Amount(60),
                    }
        })
        .map(|(i, _)| *i)
        .collect::<Vec<_>>();
    inputs.sort();
    assert_eq!(inputs.len(), 2);
    let mut participants = vec![public(10), public(11)];
    participants.sort();
    (
        root,
        node,
        Request {
            owner: public(10),
            participants,
            inputs: Some(inputs),
            outputs: vec![Payment {
                owner: public(14),
                amount: Amount(98),
            }],
            remote: None,
            fee: Amount(1),
            valid_for_blocks: 8,
            valid_through: None,
        },
    )
}
fn group_key(root: &std::path::Path, seed: u8) -> PathBuf {
    let p = root.join(format!("group-key-{seed}.json"));
    fs::write(
        &p,
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}
fn group_sign(
    agent: &mut Agent,
    node: &Store,
    req: Request,
    root: &std::path::Path,
    seed: u8,
) -> wallet_agent::Signed {
    let head = agent.journal.head().unwrap();
    let p = agent.prepare(node, req, head).unwrap();
    agent
        .sign(
            node,
            p.draft,
            &group_key(root, seed),
            p.review_commitment,
            head,
        )
        .unwrap()
}
#[test]
fn group_independent_reservations_recover_and_complete_exact_authorization() {
    let f = Fixture::new();
    let (root, mut node, req) = group_fixture(&f);
    let dir = root.join("group-wallet-10");
    let mut a = Agent::create(&dir, &node, public(10)).unwrap();
    let mut b = Agent::create(&root.join("group-wallet-11"), &node, public(11)).unwrap();
    let before = wallet::Pin::current(&node).unwrap();
    let sa = group_sign(&mut a, &node, req.clone(), &root, 10);
    assert!(!sa.retained_approvals_complete);
    assert_eq!(sa.required_owners, req.participants);
    assert_eq!(
        a.view(&node, sa.wallet_head)
            .unwrap()
            .reserved_owned_outputs,
        Amount(39)
    );
    assert_eq!(
        b.view(&node, b.journal.head().unwrap())
            .unwrap()
            .reserved_owned_outputs,
        Amount::ZERO
    );
    assert!(node.template(sa.commands.clone(), public(10)).is_err());
    assert!(wallet::combine(&node, sa.commands.clone()).is_err());
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), sa.commands[0].clone()]).is_err());
    assert_eq!(wallet::Pin::current(&node).unwrap(), before);
    drop(a);
    fs::remove_file(group_key(&root, 10)).unwrap();
    let a = Agent::open(&dir, &node).unwrap();
    let retry = a.recover(&node, sa.intent_id, sa.wallet_head).unwrap();
    assert_eq!(retry.commands, sa.commands);
    assert!(!retry.retained_approvals_complete);
    let mut rb = req;
    rb.owner = public(11);
    let sb = group_sign(&mut b, &node, rb, &root, 11);
    assert_eq!(sb.intent_id, sa.intent_id);
    assert_eq!(
        b.view(&node, sb.wallet_head)
            .unwrap()
            .reserved_owned_outputs,
        Amount(60)
    );
    let mut bad = sb.commands[0].clone();
    if let Command::Spend(s) = &mut bad {
        s.approvals[0].signature = "00".repeat(64);
    }
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), bad]).is_err());
    let mut bad = sb.commands[0].clone();
    if let Command::Spend(s) = &mut bad {
        s.intent.outputs[0].owner = public(13);
    }
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), bad]).is_err());
    let mut bad = sb.commands[0].clone();
    if let Command::Spend(s) = &mut bad {
        s.approvals[0].key = public(12);
    }
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), bad]).is_err());
    let combined = wallet::combine(
        &node,
        vec![sb.commands[0].clone(), retry.commands[0].clone()],
    )
    .unwrap();
    assert!(combined.complete_owner_authorization);
    assert_eq!(combined.intent_id, sa.intent_id);
    assert_eq!(wallet::Pin::current(&node).unwrap(), before);
    let mut incomplete = node
        .template(combined.commands.clone(), public(10))
        .unwrap();
    if let Command::Spend(signed) = &mut incomplete.commands[0] {
        signed.approvals.pop();
    }
    incomplete.header.commands = id("commands", &incomplete.commands).unwrap();
    mine(&mut incomplete).unwrap();
    assert!(node.accept(incomplete).is_err());
    assert_eq!(wallet::Pin::current(&node).unwrap(), before);
    step(&mut node, combined.commands.clone());
    for (agent, signed) in [(&a, &sa), (&b, &sb)] {
        let view = agent.view(&node, signed.wallet_head).unwrap();
        assert_eq!(view.signed[0].state, "INCLUDED_IN_LOCAL_LEDGER");
        assert_eq!(view.reserved_owned_outputs, Amount::ZERO);
        assert!(!view.signed[0].retained_approvals_complete);
    }
    assert_eq!(
        wallet::view(&node, &public(14)).unwrap().spendable,
        Amount(98)
    );
    assert!(node.template(combined.commands, public(10)).is_err());
    assert_eq!(node.chain.ledger.minted, Amount(300));
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn group_full_review_rejects_faked_ownership_amounts_and_unbalanced_requests() {
    let f = Fixture::new();
    let (root, node, req) = group_fixture(&f);
    let mut a = Agent::create(&root.join("wallet"), &node, public(10)).unwrap();
    let head = a.journal.head().unwrap();
    let p = a.prepare(&node, req.clone(), head).unwrap();
    for mode in 0..3 {
        let mut bad = p.draft.clone();
        let input = bad.intent.inputs[0];
        match mode {
            0 => {
                bad.input_owners.insert(input, public(12));
            }
            1 => {
                bad.input_amounts.insert(input, Amount(999));
            }
            _ => {
                bad.intent.outputs[0].owner = public(12);
            }
        }
        let review = id("wallet-reviewed-draft", &bad).unwrap();
        assert!(a
            .sign(&node, bad, &group_key(&root, 10), review, head)
            .is_err());
    }
    for mode in 0..4 {
        let mut bad = req.clone();
        match mode {
            0 => bad.inputs = None,
            1 => bad.participants.push(public(12)),
            2 => bad.outputs[0].amount = Amount(97),
            _ => bad.inputs.as_mut().unwrap().push(p.draft.intent.inputs[0]),
        }
        assert!(a.prepare(&node, bad, head).is_err());
    }
    assert_eq!(a.journal.head().unwrap(), head);
    assert!(a.journal.records.is_empty());
    group_sign(&mut a, &node, req, &root, 10);
    let retained = a.journal.clone();
    let dir = root.join("wallet");
    drop(a);
    for mode in 0..2 {
        let mut bad = retained.clone();
        let draft = &mut bad.records[0].draft;
        let input = draft.intent.inputs[0];
        if mode == 0 {
            draft.input_owners.insert(input, public(12));
        } else {
            draft.input_amounts.insert(input, Amount(999));
        }
        bad.records[0].review_commitment =
            id("wallet-reviewed-draft", &bad.records[0].draft).unwrap();
        let bytes = serde_json::to_vec(&bad).unwrap();
        fs::write(dir.join("wallet.json"), &bytes).unwrap();
        assert!(Agent::open(&dir, &node).is_err());
        assert_eq!(fs::read(dir.join("wallet.json")).unwrap(), bytes);
    }
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn group_native_expiry_retains_partial_signatures_and_releases_only_own_inputs() {
    let f = Fixture::new();
    let (root, mut node, mut req) = group_fixture(&f);
    req.valid_for_blocks = 1;
    let mut a = Agent::create(&root.join("wallet-a"), &node, public(10)).unwrap();
    let mut b = Agent::create(&root.join("wallet-b"), &node, public(11)).unwrap();
    let sa = group_sign(&mut a, &node, req.clone(), &root, 10);
    req.owner = public(11);
    let sb = group_sign(&mut b, &node, req, &root, 11);
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), sb.commands[0].clone()]).is_ok());
    step(&mut node, vec![]);
    assert!(wallet::combine(&node, vec![sa.commands[0].clone(), sb.commands[0].clone()]).is_err());
    for (agent, signed) in [(&a, &sa), (&b, &sb)] {
        let v = agent.view(&node, signed.wallet_head).unwrap();
        assert_eq!(v.reserved_owned_outputs, Amount::ZERO);
        assert_eq!(v.signed[0].state, "EXPIRED_BEFORE_INCLUSION");
        assert_eq!(
            agent
                .recover(&node, signed.intent_id, signed.wallet_head)
                .unwrap()
                .commands,
            signed.commands
        );
        assert_eq!(agent.journal.records.len(), 1);
    }
    assert_eq!(
        wallet::view(&node, &public(11)).unwrap().spendable,
        Amount(60)
    );
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn group_consumed_peer_input_invalidates_intent_without_consuming_own_input() {
    let f = Fixture::new();
    let (root, mut node, req) = group_fixture(&f);
    let own = req
        .inputs
        .as_ref()
        .unwrap()
        .iter()
        .find(|i| node.chain.ledger.coins[i].payment.owner == public(10))
        .copied()
        .unwrap();
    let peer = req
        .inputs
        .as_ref()
        .unwrap()
        .iter()
        .find(|i| node.chain.ledger.coins[i].payment.owner == public(11))
        .copied()
        .unwrap();
    let mut a = Agent::create(&root.join("wallet"), &node, public(10)).unwrap();
    let sa = group_sign(&mut a, &node, req.clone(), &root, 10);
    // Deliberate other-key operation, representing a separately authorized peer command.
    let mut other = request();
    other.owner = public(11);
    other.inputs = Some(vec![peer]);
    other.outputs[0].amount = Amount(59);
    let d = wallet::prepare(&node, other).unwrap();
    let review = id("wallet-reviewed-draft", &d).unwrap();
    let cmd = wallet::sign(&node, d, &group_key(&root, 11), review).unwrap();
    step(&mut node, vec![cmd]);
    let v = a.view(&node, sa.wallet_head).unwrap();
    assert_eq!(v.signed[0].state, "INPUTS_CONSUMED_BY_OTHER_LOCAL_COMMAND");
    assert_eq!(v.reserved_owned_outputs, Amount::ZERO);
    assert!(node.chain.ledger.coins.contains_key(&own));
    assert!(a.prepare(&node, req, sa.wallet_head).is_err());
    let mut next = request();
    next.inputs = Some(vec![own]);
    let signed = group_sign(&mut a, &node, next, &root, 10);
    assert!(signed.retained_approvals_complete);
    assert_eq!(a.journal.records.len(), 2);
    drop(a);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn group_fixed_proposal_preserves_intent_across_later_independent_reviews() {
    let f = Fixture::new();
    let (root, mut node, mut req) = group_fixture(&f);
    req.valid_through = Some(node.chain.height() + 8);
    let mut a = Agent::create(&root.join("group-wallet-a"), &node, public(10)).unwrap();
    let first = group_sign(&mut a, &node, req.clone(), &root, 10);
    step(&mut node, vec![]);
    let mut b = Agent::create(&root.join("group-wallet-b"), &node, public(11)).unwrap();
    req.owner = public(11);
    let second = group_sign(&mut b, &node, req, &root, 11);
    assert_eq!(first.intent_id, second.intent_id);
    let parts = vec![first.commands[0].clone(), second.commands[0].clone()];
    let combined = wallet::combine(&node, parts).unwrap();
    step(&mut node, combined.commands);
    assert_eq!(
        a.view(&node, a.journal.head().unwrap())
            .unwrap()
            .reserved_owned_outputs,
        Amount::ZERO
    );
    assert_eq!(
        b.view(&node, b.journal.head().unwrap())
            .unwrap()
            .reserved_owned_outputs,
        Amount::ZERO
    );
    assert_eq!(node.chain.ledger.minted, Amount(300));
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn group_fixed_expiry_rejects_past_overlong_and_mutated_proposals() {
    let f = Fixture::new();
    let (root, node, mut req) = group_fixture(&f);
    for expiry in [0, node.chain.height(), node.chain.height() + 33, u64::MAX] {
        req.valid_through = Some(expiry);
        assert!(wallet::prepare(&node, req.clone()).is_err());
    }
    req.valid_through = Some(node.chain.height() + 8);
    let draft = wallet::prepare(&node, req).unwrap();
    let review = id("wallet-reviewed-draft", &draft).unwrap();
    let mut altered = draft;
    altered.request.valid_through = Some(node.chain.height() + 9);
    assert!(wallet::sign(&node, altered, &group_key(&root, 10), review).is_err());
    let mut single = request();
    single.valid_through = Some(node.chain.height() + 8);
    assert!(wallet::prepare(&node, single).is_err());
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
