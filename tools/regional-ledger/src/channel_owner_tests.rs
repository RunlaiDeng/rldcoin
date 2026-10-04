use super::*;
use crate::tests::{
    channel_receipts::{certify, head, receipt, selected, setup},
    public, signature,
};
use std::os::unix::fs::PermissionsExt;
fn key(root: &Path, seed: u8) -> PathBuf {
    let p = root.join(format!("key-{seed}.json"));
    fs::write(
        &p,
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}
fn owners(root: &Path, node: &Store, channel: Hash) -> (Agent, Agent) {
    (
        Agent::create_component(&root.join("alice"), node, channel, public(10), head(root))
            .unwrap(),
        Agent::create_component(&root.join("bob"), node, channel, public(11), head(root)).unwrap(),
    )
}
fn sign(agent: &mut Agent, node: &Store, root: &Path, request: Request, seed: u8) -> Response {
    let owner_head = agent.head().unwrap();
    let native = head(root);
    let reviewed = agent
        .prepare_component(node, &request, owner_head, native)
        .unwrap();
    let path = root.join(format!("key-{seed}.json"));
    agent
        .sign_component(node, request, &path, reviewed, owner_head, native)
        .unwrap()
}
fn start(root: &Path, node: &Store, a: &mut Agent, b: &mut Agent) -> c::SignedState {
    key(root, 10);
    key(root, 11);
    let request = a.initial_request(node).unwrap();
    let one = sign(a, node, root, request.clone(), 10);
    let two = sign(b, node, root, request, 11);
    assert!(!one.approvals_complete && one.first_signed_this_call);
    let Combined::Initial(s) = combine(node, vec![one.partial, two.partial], head(root)).unwrap()
    else {
        panic!()
    };
    s
}
fn draft(mut r: r::Receipt) -> Request {
    r.next.approvals.clear();
    r.approvals.clear();
    Request::Payment(Box::new(r))
}
fn finish(node: &Store, root: &Path, a: &mut Agent, b: &mut Agent, request: Request) -> r::Receipt {
    let first = sign(a, node, root, request.clone(), 10);
    let second = sign(b, node, root, request, 11);
    let Combined::Payment(r) =
        combine(node, vec![first.partial, second.partial], head(root)).unwrap()
    else {
        panic!()
    };
    *r
}
#[test]
fn native_channel_owner_two_real_partial_signers_combine_accept_restart_and_keyless_recover() {
    let (root, mut node, channel, reserve) = setup(Some(3));
    let reserve = reserve.unwrap();
    let ledger = node.chain.ledger.clone();
    let (mut a, mut b) = owners(&root, &node, channel);
    let initial = start(&root, &node, &mut a, &mut b);
    let request = draft(receipt(&node, reserve, 1, initial, 10, None));
    let before = a.head().unwrap();
    let r = finish(&node, &root, &mut a, &mut b, request.clone());
    assert_eq!(a.journal.records.len(), 2);
    assert_eq!(a.journal.records[1].partial.state_approval.key, public(10));
    assert_ne!(a.head().unwrap(), before);
    assert_eq!(node.chain.ledger, ledger);
    node.accept_channel_receipt(r.clone(), &r.statement.expected, head(&root))
        .unwrap();
    let nh = head(&root);
    let ah = a.head().unwrap();
    let authority = public(1);
    let pin = node.trust.currency().unwrap();
    let reviewed_request = review(a.binding(), &request).unwrap();
    drop(a);
    drop(b);
    drop(node);
    let mut node = Store::open_pinned(&root.join("earth"), &authority, pin, nh).unwrap();
    let mut a = Agent::open(&root.join("alice"), &node).unwrap();
    let mut b = Agent::open(&root.join("bob"), &node).unwrap();
    fs::remove_file(root.join("key-10.json")).unwrap();
    let recovered = a
        .recover_component(&node, &request, reviewed_request, ah, nh)
        .unwrap();
    assert!(recovered.recovered_exact_response && !recovered.first_signed_this_call);
    assert_eq!(recovered.partial.request, request);
    let next = draft(receipt(
        &node,
        reserve,
        2,
        r.next.clone(),
        -3,
        Some(r.id().unwrap()),
    ));
    let reviewed = review(a.binding(), &next).unwrap();
    let bytes = fs::read(root.join("alice/owner.json")).unwrap();
    assert!(a.recover_component(&node, &next, reviewed, ah, nh).is_err());
    assert_eq!(fs::read(root.join("alice/owner.json")).unwrap(), bytes);
    key(&root, 10);
    let second = finish(&node, &root, &mut a, &mut b, next);
    node.accept_channel_receipt(second.clone(), &second.statement.expected, head(&root))
        .unwrap();
    assert_eq!(node.chain.ledger, ledger);
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_owner_highest_signed_not_accepted_locks_conflicts_and_malformed_prior() {
    let (root, node, channel, reserve) = setup(Some(3));
    let (mut a, mut b) = owners(&root, &node, channel);
    let initial = start(&root, &node, &mut a, &mut b);
    let request = draft(receipt(
        &node,
        reserve.unwrap(),
        1,
        initial.clone(),
        10,
        None,
    ));
    let old = a.head().unwrap();
    let response = sign(&mut a, &node, &root, request.clone(), 10);
    let ah = response.owner_head;
    assert!(combine(&node, vec![response.partial.clone()], head(&root)).is_err());
    let Request::Payment(r) = &request else {
        panic!()
    };
    assert!(r.verify_anchor(&node.trust, &node.evidence).is_err());
    let alternate = draft(receipt(&node, reserve.unwrap(), 2, initial, 20, None));
    let disk = fs::read(root.join("alice/owner.json")).unwrap();
    assert!(a
        .prepare_component(&node, &alternate, ah, head(&root))
        .is_err());
    assert!(a
        .sign_component(
            &node,
            alternate.clone(),
            &root.join("key-10.json"),
            review(a.binding(), &alternate).unwrap(),
            old,
            head(&root)
        )
        .is_err());
    let mut complete = *r.clone();
    complete.next.approvals = vec![
        Approval {
            key: public(10),
            signature: signature(10, &complete.next.statement.bytes().unwrap()),
        },
        Approval {
            key: public(11),
            signature: signature(11, &complete.next.statement.bytes().unwrap()),
        },
    ];
    complete.next.approvals.sort_by(|a, b| a.key.cmp(&b.key));
    let mut next = receipt(
        &node,
        reserve.unwrap(),
        3,
        complete.next.clone(),
        -1,
        Some(complete.id().unwrap()),
    );
    next.prior.approvals[0].signature = "00".into();
    assert!(a
        .prepare_component(&node, &draft(next), ah, head(&root))
        .is_err());
    let next = draft(receipt(
        &node,
        reserve.unwrap(),
        3,
        complete.next.clone(),
        -1,
        None,
    ));
    assert!(a.prepare_component(&node, &next, ah, head(&root)).is_err());
    let previous_id = complete.id().unwrap();
    let next = draft(receipt(
        &node,
        reserve.unwrap(),
        1,
        complete.next,
        -1,
        Some(previous_id),
    ));
    assert!(a.prepare_component(&node, &next, ah, head(&root)).is_err());
    assert_eq!(fs::read(root.join("alice/owner.json")).unwrap(), disk);
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_owner_pending_exact_response_requires_explicit_keyless_recovery_and_never_first_signs(
) {
    let (root, node, channel, reserve) = setup(Some(3));
    let (mut a, mut b) = owners(&root, &node, channel);
    let initial = start(&root, &node, &mut a, &mut b);
    let previous = fs::read(root.join("alice/owner.json")).unwrap();
    let old = a.head().unwrap();
    let request = draft(receipt(&node, reserve.unwrap(), 1, initial, 10, None));
    let reviewed = review(a.binding(), &request).unwrap();
    let response = sign(&mut a, &node, &root, request.clone(), 10);
    let candidate = fs::read(root.join("alice/owner.json")).unwrap();
    drop(a);
    fs::write(root.join("alice/owner.json"), &previous).unwrap();
    crate::keystore::private_create(&root.join("alice/owner.next"), &candidate).unwrap();
    fs::remove_file(root.join("key-10.json")).unwrap();
    let mut a = Agent::open(&root.join("alice"), &node).unwrap();
    assert!(a.pending.is_some());
    assert_eq!(fs::read(root.join("alice/owner.json")).unwrap(), previous);
    assert!(a
        .prepare_component(&node, &request, old, head(&root))
        .is_err());
    assert!(a
        .recover_component(&node, &request, Hash::ZERO, old, head(&root))
        .is_err());
    assert!(a
        .recover_component(&node, &request, reviewed, Hash::ZERO, head(&root))
        .is_err());
    assert!(root.join("alice/owner.next").exists());
    let exact = a
        .recover_component(&node, &request, reviewed, old, head(&root))
        .unwrap();
    assert_eq!(exact.partial, response.partial);
    assert_eq!(exact.owner_head, response.owner_head);
    assert!(!root.join("alice/owner.next").exists());
    assert_eq!(fs::read(root.join("alice/owner.json")).unwrap(), candidate);
    let Request::Payment(mut next) = request.clone() else {
        panic!()
    };
    next.statement.expected.invoice = Hash([7; 32]);
    let next = Request::Payment(next);
    assert!(a
        .recover_component(
            &node,
            &next,
            review(a.binding(), &next).unwrap(),
            response.owner_head,
            head(&root)
        )
        .is_err());
    drop(a);
    let mut bad: Journal = serde_json::from_slice(&candidate).unwrap();
    bad.records
        .last_mut()
        .unwrap()
        .partial
        .state_approval
        .signature = "00".into();
    fs::write(root.join("alice/owner.json"), &previous).unwrap();
    crate::keystore::private_create(
        &root.join("alice/owner.next"),
        &serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    let raw = fs::read(root.join("alice/owner.next")).unwrap();
    assert!(Agent::open(&root.join("alice"), &node).is_err());
    assert_eq!(fs::read(root.join("alice/owner.next")).unwrap(), raw);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_owner_stale_owner_native_heads_wrong_key_purpose_and_incomplete_creation_refuse()
{
    let (root, node, channel, _) = setup(Some(3));
    let (mut a, mut b) = owners(&root, &node, channel);
    let old = fs::read(root.join("alice/owner.json")).unwrap();
    let oldhead = a.head().unwrap();
    let initial = start(&root, &node, &mut a, &mut b);
    let current = a.head().unwrap();
    let request = a.initial_request(&node).unwrap();
    assert!(a
        .recover_component(
            &node,
            &request,
            review(a.binding(), &request).unwrap(),
            current,
            Hash::ZERO
        )
        .is_err());
    let mut parts = a.journal.records[0].partial.clone();
    parts.binding.purpose = "wallet".into();
    assert!(parts.verify(&node).is_err());
    drop(a);
    fs::write(root.join("alice/owner.json"), &old).unwrap();
    let a = Agent::open(&root.join("alice"), &node).unwrap();
    assert!(a.current(&node, current, head(&root)).is_err());
    assert_eq!(a.head().unwrap(), oldhead);
    drop(a);
    crate::keystore::private_create(&root.join("alice/CREATING"), b"interrupted creation").unwrap();
    assert!(Agent::open(&root.join("alice"), &node).is_err());
    assert!(
        Agent::create_component(&root.join("alice"), &node, channel, public(10), head(&root))
            .is_err()
    );
    assert_eq!(initial.statement.sequence, 0);
    let mut c =
        Agent::create_component(&root.join("other"), &node, channel, public(10), head(&root))
            .unwrap();
    let req = c.initial_request(&node).unwrap();
    assert!(c
        .sign_component(
            &node,
            req.clone(),
            &root.join("key-11.json"),
            review(c.binding(), &req).unwrap(),
            c.head().unwrap(),
            head(&root)
        )
        .is_err());
    assert!(c.journal.records.is_empty());
    drop(c);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_owner_missing_reserve_and_current_closed_funding_never_sign_but_recovery_is_historical(
) {
    let (root, mut node, channel, _) = setup(None);
    let (mut a, mut b) = owners(&root, &node, channel);
    let initial = start(&root, &node, &mut a, &mut b);
    let request = draft(receipt(&node, Hash([9; 32]), 1, initial.clone(), 10, None));
    assert!(a
        .prepare_component(&node, &request, a.head().unwrap(), head(&root))
        .is_err());
    let initial_req = a.journal.records[0].partial.request.clone();
    let ah = a.head().unwrap();
    let reviewed = review(a.binding(), &initial_req).unwrap();
    let before = head(&root);
    let fee_input = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.payment.owner == public(10) && coin.mature <= node.chain.height() + 1
        })
        .unwrap()
        .0;
    let close = crate::tests::channel_integration::command(
        &node.chain,
        &node.trust,
        c::Action::Close {
            channel,
            state: Box::new(initial),
            fee_input,
            fee: Amount(1),
        },
        Some(10),
        &[10],
    );
    selected(&mut node, vec![close]);
    certify(&mut node);
    assert!(a
        .prepare_component(&node, &request, ah, head(&root))
        .is_err());
    assert!(a
        .recover_component(&node, &initial_req, reviewed, ah, before)
        .is_err());
    let exact = a
        .recover_component(&node, &initial_req, reviewed, ah, head(&root))
        .unwrap();
    assert!(!exact.first_signed_this_call);
    assert!(
        Agent::create_component(&root.join("later"), &node, channel, public(10), head(&root))
            .is_err()
    );
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_owner_publication_failure_no_ack_and_capacity_retains_highest_signed_state() {
    let (root, node, channel, reserve) = setup(Some(3));
    let (mut a, mut b) = owners(&root, &node, channel);
    let mut prior = start(&root, &node, &mut a, &mut b);
    let mut previous = None;
    let observation = Observation::current(&node).unwrap();
    for i in 1..MAX_SIGNED {
        let full = receipt(
            &node,
            reserve.unwrap(),
            i as u64,
            prior,
            if i % 2 == 1 { 1 } else { -1 },
            previous,
        );
        let request = draft(full.clone());
        let reviewed = review(a.binding(), &request).unwrap();
        let partial = Partial {
            binding: a.binding().clone(),
            request,
            state_approval: Approval {
                key: public(10),
                signature: signature(10, &full.next.statement.bytes().unwrap()),
            },
            invoice_approval: Some(Approval {
                key: public(10),
                signature: signature(10, &full.statement.bytes().unwrap()),
            }),
        };
        let record = Record {
            previous_head: a.head().unwrap(),
            observation: observation.clone(),
            review: reviewed,
            partial,
        };
        a.journal.records.push(record);
        previous = Some(full.id().unwrap());
        prior = full.next;
    }
    a.journal.validate(&node).unwrap();
    a.persist(&a.journal).unwrap();
    let current = a.head().unwrap();
    let request = draft(receipt(&node, reserve.unwrap(), 1000, prior, -1, previous));
    let reviewed = review(a.binding(), &request).unwrap();
    let raw = fs::read(root.join("alice/owner.json")).unwrap();
    assert!(a
        .sign_component(
            &node,
            request,
            &root.join("key-10.json"),
            reviewed,
            current,
            head(&root)
        )
        .is_err());
    assert_eq!(fs::read(root.join("alice/owner.json")).unwrap(), raw);
    let mut other =
        Agent::create_component(&root.join("other"), &node, channel, public(10), head(&root))
            .unwrap();
    let request = other.initial_request(&node).unwrap();
    let reviewed = review(other.binding(), &request).unwrap();
    let before = other.head().unwrap();
    crate::keystore::private_create(&root.join("other/owner.next"), b"unchanged failure residue")
        .unwrap();
    assert!(other
        .sign_component(
            &node,
            request.clone(),
            &root.join("key-10.json"),
            reviewed,
            before,
            head(&root)
        )
        .is_err());
    assert!(!other.healthy && other.journal.records.is_empty());
    assert!(other
        .recover_component(&node, &request, reviewed, before, head(&root))
        .is_err());
    assert_eq!(
        fs::read(root.join("other/owner.next")).unwrap(),
        b"unchanged failure residue"
    );
    drop(other);
    drop(a);
    drop(b);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
