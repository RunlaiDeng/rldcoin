use super::*;
use crate::tests::{
    channel_receipts::{head, receipt, setup, setup_witness},
    public,
};
use std::os::unix::fs::PermissionsExt;
fn key(root: &Path, seed: u8) -> PathBuf {
    let p = root.join(format!("fixture-{seed}.json"));
    fs::write(
        &p,
        serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    p
}
fn sign(
    a: &mut Agent,
    w: &mut Witness,
    node: &Store,
    root: &Path,
    request: Request,
    seed: u8,
) -> Witnessed {
    let h = a.head().unwrap();
    let wh = w.head().unwrap();
    let review = a
        .prepare_witnessed(node, &request, (h, head(root)), w, wh)
        .unwrap();
    a.sign_witnessed(
        node,
        Reviewed {
            request,
            review,
            owner_head: h,
            native_head: head(root),
        },
        &root.join(format!("fixture-{seed}.json")),
        w,
        &root.join("fixture-12.json"),
        wh,
    )
    .unwrap()
}
#[test]
fn native_channel_witness_two_owners_original_continuation_keyless_restart_and_reset_refusal() {
    let (root, node, channel, reserve) = setup_witness(Some(3));
    key(&root, 10);
    key(&root, 11);
    let wk = key(&root, 12);
    let mut w = Witness::create(&root.join("witness"), &node, public(12), head(&root)).unwrap();
    let wh_a = w.head().unwrap();
    let mut a = Agent::create_witnessed(
        &root.join("alice"),
        &node,
        channel,
        public(10),
        head(&root),
        &mut w,
        (&wk, wh_a),
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
    let Combined::Initial(initial) = combine(
        &node,
        vec![one.owner.partial, two.owner.partial],
        head(&root),
    )
    .unwrap() else {
        panic!()
    };
    let mut r = receipt(&node, reserve.unwrap(), 1, initial, 10, None);
    r.next.approvals.clear();
    r.approvals.clear();
    let req = Request::Payment(Box::new(r));
    let one = sign(&mut a, &mut w, &node, &root, req.clone(), 10);
    let two = sign(&mut b, &mut w, &node, &root, req.clone(), 11);
    let Combined::Payment(r) = combine(
        &node,
        vec![one.owner.partial.clone(), two.owner.partial],
        head(&root),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(r.next.statement.sequence, 1);
    let wh = w.head().unwrap();
    assert!(Agent::create_witnessed(
        &root.join("reset"),
        &node,
        channel,
        public(10),
        head(&root),
        &mut w,
        (&wk, wh)
    )
    .is_err());
    assert!(!root.join("reset").exists());
    let ah = a.head().unwrap();
    let reviewed = review(a.binding(), &req).unwrap();
    drop(a);
    drop(b);
    drop(w);
    fs::remove_file(root.join("fixture-10.json")).unwrap();
    fs::remove_file(&wk).unwrap();
    let mut w = Witness::open(&root.join("witness"), &node).unwrap();
    let mut a = Agent::open(&root.join("alice"), &node).unwrap();
    let response = a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: ah,
                native_head: head(&root),
            },
            &mut w,
            wh,
        )
        .unwrap();
    assert_eq!(response.owner.partial, one.owner.partial);
    assert!(!response.owner.first_signed_this_call);
    assert_eq!(response.witness_head, wh);
    drop(a);
    drop(w);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_witness_missing_policy_role_head_or_original_state_is_readonly() {
    let (root, node, channel, _) = setup(None);
    let wk = key(&root, 12);
    let mut w = Witness::create(&root.join("witness"), &node, public(12), head(&root)).unwrap();
    let wh = w.head().unwrap();
    assert!(Agent::create_witnessed(
        &root.join("alice"),
        &node,
        channel,
        public(10),
        head(&root),
        &mut w,
        (&wk, wh)
    )
    .is_err());
    assert!(!root.join("alice").exists());
    assert!(Agent::create(&root.join("bare"), &node, channel, public(10), head(&root)).is_err());
    drop(w);
    drop(node);
    fs::remove_dir_all(root).unwrap();
    let (root, node, channel, _) = setup_witness(Some(3));
    key(&root, 10);
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
    let old = fs::read(root.join("alice/owner.json")).unwrap();
    let req = a.initial_request(&node).unwrap();
    let first = sign(&mut a, &mut w, &node, &root, req.clone(), 10);
    let wh = w.head().unwrap();
    assert!(a
        .prepare_witnessed(
            &node,
            &req,
            (first.owner.owner_head, head(&root)),
            &w,
            Hash::ZERO
        )
        .is_err());
    drop(a);
    fs::write(root.join("alice/owner.json"), old).unwrap();
    let a = Agent::open(&root.join("alice"), &node).unwrap();
    assert!(a
        .prepare_witnessed(&node, &req, (a.head().unwrap(), head(&root)), &w, wh)
        .is_err());
    let mut wrong = Witness::create(&root.join("wrong"), &node, public(13), head(&root)).unwrap();
    let whead = wrong.head().unwrap();
    assert!(Agent::create_witnessed(
        &root.join("other"),
        &node,
        channel,
        public(11),
        head(&root),
        &mut wrong,
        (&wk, whead)
    )
    .is_err());
    drop(wrong);
    drop(a);
    drop(w);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_witness_commit_gap_never_releases_and_keyless_recovery_cannot_first_attest() {
    let (root, node, channel, _) = setup_witness(Some(3));
    let ownkey = key(&root, 10);
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
    let ah = a.head().unwrap();
    let req = a.initial_request(&node).unwrap();
    let reviewed = a
        .prepare_witnessed(&node, &req, (ah, head(&root)), &w, wh)
        .unwrap();
    // Wrong role key refuses the witness publication after durable own signature.
    let wrong = key(&root, 11);
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
    let retained = a.head().unwrap();
    assert_ne!(retained, ah);
    assert_eq!(w.head().unwrap(), wh);
    assert!(a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: ah,
                native_head: head(&root)
            },
            &mut w,
            wh
        )
        .is_err());
    fs::remove_file(&ownkey).unwrap();
    let completed = a
        .finish_witness(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: ah,
                native_head: head(&root),
            },
            &mut w,
            &wk,
            wh,
        )
        .unwrap();
    assert!(!completed.owner.first_signed_this_call);
    let wh = completed.witness_head;
    let exact = a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: retained,
                native_head: head(&root),
            },
            &mut w,
            wh,
        )
        .unwrap();
    assert_eq!(exact.owner.partial, completed.owner.partial);
    assert!(!root.join("fixture-10.json").exists());
    drop(a);
    drop(w);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn native_channel_witness_signed_pending_promotes_only_exact_retained_response_and_corruption_refuses(
) {
    let (root, node, channel, _) = setup_witness(Some(3));
    key(&root, 10);
    let wk = key(&root, 12);
    let mut w = Witness::create(&root.join("witness"), &node, public(12), head(&root)).unwrap();
    let h = w.head().unwrap();
    let mut a = Agent::create_witnessed(
        &root.join("alice"),
        &node,
        channel,
        public(10),
        head(&root),
        &mut w,
        (&wk, h),
    )
    .unwrap();
    key(&root, 11);
    let wh_b = w.head().unwrap();
    let mut b = Agent::create_witnessed(
        &root.join("bob"),
        &node,
        channel,
        public(11),
        head(&root),
        &mut w,
        (&wk, wh_b),
    )
    .unwrap();
    let req_b = b.initial_request(&node).unwrap();
    sign(&mut b, &mut w, &node, &root, req_b.clone(), 11);
    let old = fs::read(root.join("witness/witness.json")).unwrap();
    let wh = w.head().unwrap();
    let req = a.initial_request(&node).unwrap();
    let signed = sign(&mut a, &mut w, &node, &root, req.clone(), 10);
    let next = fs::read(root.join("witness/witness.json")).unwrap();
    drop(w);
    fs::write(root.join("witness/witness.json"), &old).unwrap();
    crate::keystore::private_create(&root.join("witness/witness.next"), &next).unwrap();
    let mut w = Witness::open(&root.join("witness"), &node).unwrap();
    assert!(w.pending.is_some());
    assert_eq!(fs::read(root.join("witness/witness.json")).unwrap(), old);
    let ah = a.head().unwrap();
    let reviewed = review(a.binding(), &req).unwrap();
    assert!(a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: Hash::ZERO,
                owner_head: ah,
                native_head: head(&root)
            },
            &mut w,
            wh
        )
        .is_err());
    assert!(root.join("witness/witness.next").exists());
    assert!(a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: Hash::ZERO,
                native_head: head(&root)
            },
            &mut w,
            wh,
        )
        .is_err());
    assert!(root.join("witness/witness.next").exists());
    assert_eq!(fs::read(root.join("witness/witness.json")).unwrap(), old);
    assert!(b
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req_b.clone(),
                review: review(b.binding(), &req_b).unwrap(),
                owner_head: b.head().unwrap(),
                native_head: head(&root)
            },
            &mut w,
            wh,
        )
        .is_err());
    assert!(root.join("witness/witness.next").exists());
    assert_eq!(fs::read(root.join("witness/witness.json")).unwrap(), old);
    let recovered = a
        .recover_witnessed(
            &node,
            &Reviewed {
                request: req.clone(),
                review: reviewed,
                owner_head: ah,
                native_head: head(&root),
            },
            &mut w,
            wh,
        )
        .unwrap();
    assert_eq!(recovered.owner.partial, signed.owner.partial);
    assert!(!root.join("witness/witness.next").exists());
    drop(w);
    let mut bad: WitnessJournal = serde_json::from_slice(&next).unwrap();
    bad.entries.last_mut().unwrap().approval.signature = "00".into();
    fs::write(root.join("witness/witness.json"), &old).unwrap();
    crate::keystore::private_create(
        &root.join("witness/witness.next"),
        &serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    let bytes = fs::read(root.join("witness/witness.next")).unwrap();
    assert!(Witness::open(&root.join("witness"), &node).is_err());
    assert_eq!(fs::read(root.join("witness/witness.next")).unwrap(), bytes);
    drop(b);
    drop(a);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
