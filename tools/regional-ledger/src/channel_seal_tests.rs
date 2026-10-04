use super::*;
use crate::tests::{
    channel_receipts::{head, receipt, setup_witness},
    public, signature,
};
#[test]
fn native_channel_state_witness_missing_role_invoice_and_replaced_inception_refuse_without_native_changes(
) {
    let (root, mut node, channel, reserve) = setup_witness(Some(3));
    let native = node.chain.ledger.channel_state.as_ref().unwrap();
    let initial = crate::tests::channel_integration::signed_state(
        &node.chain,
        &node.trust,
        channel,
        0,
        [Amount(60), Amount::ZERO],
    );
    let mut missing = initial.clone();
    missing.witness = None;
    assert!(native.book.channels[&channel]
        .verify_state(&missing, channel, &native.declaration)
        .unwrap_err()
        .contains("witness"));
    let mut command = crate::tests::channel_integration::funding(&node.chain, &node.trust);
    if let Command::Channel(c) = &mut command {
        if let c::Action::Open { witness, .. } = &mut c.action.intent.action {
            *witness = None;
        }
        c.action.approvals = [10, 11]
            .into_iter()
            .map(|seed| Approval {
                key: public(seed),
                signature: signature(seed, &c.action.intent.bytes().unwrap()),
            })
            .collect();
        c.action.approvals.sort_by(|a, b| a.key.cmp(&b.key));
    }
    let before = node.chain.ledger.clone();
    let native_head = head(&root);
    assert!(node
        .template(vec![command], public(10))
        .unwrap_err()
        .contains("witness"));
    let first = receipt(&node, reserve.unwrap(), 1, initial, 10, None);
    for kind in 0..3 {
        let mut bad = first.clone();
        if kind == 0 {
            bad.next.witness = None;
        }
        if kind == 1 {
            let p = bad.next.witness.as_mut().unwrap();
            p.approval.key = public(13);
            p.approval.signature = signature(13, &p.statement.bytes().unwrap());
        }
        if kind == 2 {
            let p = bad.next.witness.as_mut().unwrap();
            p.statement.invoice.as_mut().unwrap().expected.invoice =
                id("other-invoice", &1).unwrap();
            p.approval.signature = signature(12, &p.statement.bytes().unwrap());
        }
        assert!(node
            .accept_channel_receipt(bad, &first.statement.expected, native_head)
            .is_err());
        assert_eq!(head(&root), native_head);
        assert_eq!(node.chain.ledger, before);
    }
    let accepted = node
        .accept_channel_receipt(first.clone(), &first.statement.expected, native_head)
        .unwrap();
    let mut second = receipt(
        &node,
        reserve.unwrap(),
        2,
        first.next.clone(),
        -1,
        Some(first.id().unwrap()),
    );
    let replacement = id("replacement-birth", &1).unwrap();
    for state in [&mut second.prior, &mut second.next] {
        let p = state.witness.as_mut().unwrap();
        p.statement.inceptions[0] = replacement;
        p.approval.signature = signature(12, &p.statement.bytes().unwrap());
    }
    // Both role signatures are real and each full state/receipt anchor validates;
    // local accepted history still refuses replacing the original authorization.
    second.verify_anchor(&node.trust, &node.evidence).unwrap();
    assert!(node
        .accept_channel_receipt(
            second.clone(),
            &second.statement.expected,
            accepted.history_head
        )
        .is_err());
    assert_eq!(head(&root), accepted.history_head);
    assert_eq!(node.chain.ledger, before);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_state_witness_unconfirmed_owner_response_cannot_seal_and_exact_pending_seal_recovers_keylessly(
) {
    use crate::channel_owner::witness::tests::{key, sign};
    use crate::tests::channel_receipts::setup_witness;
    let (root, node, channel, reserve) = setup_witness(Some(3));
    let ownkey = key(&root, 10);
    key(&root, 11);
    let wk = key(&root, 12);
    let mut w = Witness::create(&root.join("witness"), &node, public(12), head(&root)).unwrap();
    let wh = w.head().unwrap();
    let mut a = Agent::create_witnessed(
        &root.join("alice"),
        &node,
        channel,
        public(10),
        head(&root),
        &mut w,
        (&wk, wh),
    )
    .unwrap();
    let wh = w.head().unwrap();
    let mut b = Agent::create_witnessed(
        &root.join("bob"),
        &node,
        channel,
        public(11),
        head(&root),
        &mut w,
        (&wk, wh),
    )
    .unwrap();
    let req = a.initial_request(&node).unwrap();
    let one = sign(&mut a, &mut w, &node, &root, req.clone(), 10);
    let two = sign(&mut b, &mut w, &node, &root, req, 11);
    let initial_draft = combine(
        &node,
        vec![one.owner.partial, two.owner.partial],
        head(&root),
    )
    .unwrap();
    let wh = w.head().unwrap();
    let Combined::Initial(initial) = w
        .seal(&node, initial_draft.clone(), &wk, (head(&root), wh))
        .unwrap()
        .combined
    else {
        panic!()
    };
    let mut r = receipt(&node, reserve.unwrap(), 1, initial, 10, None);
    r.next.approvals.clear();
    r.next.witness = None;
    r.approvals.clear();
    let req = Request::Payment(Box::new(r));
    let ah = a.head().unwrap();
    let wh = w.head().unwrap();
    let reviewed = a
        .prepare_witnessed(&node, &req, (ah, head(&root)), &w, wh)
        .unwrap();
    let wrong = key(&root, 13);
    assert!(a
        .sign_witnessed(
            &node,
            Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: ah,
                native_head: head(&root)
            },
            &ownkey,
            &mut w,
            &wrong,
            wh
        )
        .is_err());
    let raw = a.journal.records.last().unwrap().partial.clone();
    let two = sign(&mut b, &mut w, &node, &root, req.clone(), 11);
    let draft = combine(&node, vec![raw, two.owner.partial], head(&root)).unwrap();
    let wh = w.head().unwrap();
    assert!(w
        .seal(&node, draft.clone(), &wk, (head(&root), wh))
        .is_err());
    assert!(w
        .seal(&node, initial_draft, &wk, (head(&root), wh))
        .is_err());
    assert_eq!(w.head().unwrap(), wh);
    a.finish_witness(
        &node,
        &Reviewed {
            request: req,
            review: reviewed,
            owner_head: ah,
            native_head: head(&root),
        },
        &mut w,
        &wk,
        wh,
    )
    .unwrap();
    let old = fs::read(root.join("witness/witness.json")).unwrap();
    let wh = w.head().unwrap();
    let sealed = w
        .seal(&node, draft.clone(), &wk, (head(&root), wh))
        .unwrap();
    let next = fs::read(root.join("witness/witness.json")).unwrap();
    drop(w);
    drop(a);
    drop(b);
    fs::remove_file(&wk).unwrap();
    fs::remove_file(&ownkey).unwrap();
    fs::remove_file(root.join("fixture-11.json")).unwrap();
    fs::write(root.join("witness/witness.json"), &old).unwrap();
    crate::keystore::private_create(&root.join("witness/witness.next"), &next).unwrap();
    let mut w = Witness::open(&root.join("witness"), &node).unwrap();
    let mut bad = draft.clone();
    if let Combined::Payment(r) = &mut bad {
        r.next.statement.payouts.swap(0, 1);
    }
    assert!(w.recover_seal(&node, &bad, (head(&root), wh)).is_err());
    assert!(w
        .recover_seal(&node, &draft, (head(&root), Hash::ZERO))
        .is_err());
    assert_eq!(fs::read(root.join("witness/witness.json")).unwrap(), old);
    assert_eq!(fs::read(root.join("witness/witness.next")).unwrap(), next);
    let recovered = w.recover_seal(&node, &draft, (head(&root), wh)).unwrap();
    assert_eq!(recovered.combined, sealed.combined);
    assert!(!recovered.first_sealed_this_call);
    assert!(!root.join("witness/witness.next").exists());
    assert!(!wk.exists() && !ownkey.exists() && !root.join("fixture-11.json").exists());
    drop(w);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
