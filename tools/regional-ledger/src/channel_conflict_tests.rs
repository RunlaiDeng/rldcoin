use super::*;
use crate::channels as c;
use channel_integration::{command, funding, parties, signed_state};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn selected(node: &mut Store, commands: Vec<Command>) {
    let mut block = node.template(commands, public(10)).unwrap();
    mine(&mut block).unwrap();
    node.accept(block).unwrap();
}
fn setup() -> (PathBuf, Store, channel_conflict::Conflict) {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "rld-channel-conflict-{}",
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
    let input = node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.channel_dependencies.is_empty() && coin.mature <= node.chain.height() + 1
        })
        .unwrap()
        .0
        .to_owned();
    let reserve = command(
        &node.chain,
        &node.trust,
        c::Action::Reserve {
            channel,
            input,
            fee_limit: Amount(3),
        },
        Some(10),
        &[10],
    );
    selected(&mut node, vec![reserve]);
    let anchor = node.finalize(checkpoint(&node.chain, &node.trust)).unwrap();
    let proof = channel_conflict::Conflict::canonical(
        pin,
        region,
        channel,
        anchor,
        node.journal.evidence.clone(),
        signed_state(
            &node.chain,
            &node.trust,
            channel,
            1,
            [Amount(30), Amount(30)],
        ),
        signed_state(
            &node.chain,
            &node.trust,
            channel,
            1,
            [Amount(40), Amount(20)],
        ),
    )
    .unwrap();
    proof.verify(&node.trust).unwrap();
    (root, node, proof)
}
fn snapshot(node: &mut Store) {
    node.finalize(checkpoint(&node.chain, &node.trust)).unwrap();
}
fn export(
    node: &mut Store,
    input: Hash,
    destination: Hash,
    owner: u8,
    recipient: u8,
    amount: u128,
) -> Hash {
    let change = node.chain.ledger.coins[&input]
        .payment
        .amount
        .checked_sub(Amount(amount + 1))
        .unwrap();
    let signed = intent(
        &node.chain,
        &node.trust,
        vec![input],
        vec![Payment {
            owner: public(owner),
            amount: change,
        }],
        Some(destination),
        Some(Payment {
            owner: public(recipient),
            amount: Amount(amount),
        }),
        1,
        2,
        &[owner],
    );
    let eid = signed.intent.id().unwrap();
    selected(node, vec![Command::Spend(Box::new(signed))]);
    snapshot(node);
    eid
}
fn tagged(node: &Store, cid: Hash, owner: u8) -> Hash {
    *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, coin)| {
            coin.channel_dependencies.contains(&cid)
                && coin.payment.owner == public(owner)
                && coin.payment.amount > Amount(20)
                && coin.mature <= node.chain.height() + 1
        })
        .unwrap()
        .0
}
fn cleanup(root: &Path) {
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_channel_conflict_full_funding_authentication_and_atomic_quarantine() {
    let (root, mut node, proof) = setup();
    let before = node.chain.ledger.clone();
    let head = history::manifest(&root.join("earth"))
        .unwrap()
        .head()
        .unwrap();
    let mut missing = proof.clone();
    missing.funding.snapshots.clear();
    let mut bad_sig = proof.clone();
    bad_sig.right.approvals[0].signature = "00".into();
    let mut wrong_anchor = proof.clone();
    wrong_anchor.anchor = Hash::ZERO;
    let mut compatible = proof.clone();
    compatible.right = compatible.left.clone();
    let different_sequence = channel_conflict::Conflict::canonical(
        proof.currency,
        proof.region,
        proof.channel,
        proof.anchor,
        proof.funding.clone(),
        proof.left.clone(),
        signed_state(
            &node.chain,
            &node.trust,
            proof.channel,
            2,
            [Amount(40), Amount(20)],
        ),
    )
    .unwrap();
    let nonconserving = channel_conflict::Conflict::canonical(
        proof.currency,
        proof.region,
        proof.channel,
        proof.anchor,
        proof.funding.clone(),
        proof.left.clone(),
        signed_state(
            &node.chain,
            &node.trust,
            proof.channel,
            1,
            [Amount(40), Amount(21)],
        ),
    )
    .unwrap();
    for invalid in [
        missing,
        bad_sig,
        wrong_anchor,
        compatible,
        different_sequence,
        nonconserving,
    ] {
        assert!(node.observe_conflict(invalid).is_err());
        assert_eq!(before, node.chain.ledger);
        assert_eq!(
            head,
            history::manifest(&root.join("earth"))
                .unwrap()
                .head()
                .unwrap()
        );
        assert!(node.conflicts.is_empty());
    }
    let iid = node.observe_conflict(proof.clone()).unwrap();
    assert_eq!(before, node.chain.ledger);
    assert_ne!(
        head,
        history::manifest(&root.join("earth"))
            .unwrap()
            .head()
            .unwrap()
    );
    let file = root
        .join("earth/incidents")
        .join(format!("{}.json", iid.to_hex()));
    let retained = fs::read(&file).unwrap();
    assert_eq!(iid, node.observe_conflict(proof.clone()).unwrap());
    let mut forged_later = proof.clone();
    forged_later.left.approvals[0].signature = "00".into();
    assert_eq!(forged_later.id().unwrap(), iid);
    assert!(node.observe_conflict(forged_later).is_err());
    assert_eq!(retained, fs::read(file).unwrap());
    let exposure = node.safety.exposure(&node.chain, &node.evidence).unwrap();
    assert_eq!(exposure.retained_channel_capacity, Amount(60));
    assert_eq!(exposure.quarantined_channels, vec![proof.channel]);
    assert_eq!(exposure.quarantined_reserves.len(), 1);
    assert!(exposure.retained_reserve_amount > Amount::ZERO);
    assert!(!exposure.quarantined_coins.is_empty());
    let tainted = tagged(&node, proof.channel, 10);
    let signed = intent(
        &node.chain,
        &node.trust,
        vec![tainted],
        vec![node.chain.ledger.coins[&tainted].payment.clone()],
        None,
        None,
        0,
        0,
        &[10],
    );
    assert!(node
        .template(vec![Command::Spend(Box::new(signed))], public(10))
        .is_err());
    let close = command(
        &node.chain,
        &node.trust,
        c::Action::Close {
            channel: proof.channel,
            state: Box::new(proof.left.clone()),
            fee_input: tainted,
            fee: Amount(1),
        },
        Some(10),
        &[10],
    );
    assert!(node.template(vec![close], public(10)).is_err());
    let clear = *node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.channel_dependencies.is_empty() && c.mature <= node.chain.height() + 1)
        .unwrap()
        .0;
    let signed = intent(
        &node.chain,
        &node.trust,
        vec![clear],
        vec![node.chain.ledger.coins[&clear].payment.clone()],
        None,
        None,
        0,
        0,
        &[10],
    );
    selected(&mut node, vec![Command::Spend(Box::new(signed))]);
    node.chain.ledger.audit().unwrap();
    assert_eq!(
        node.chain
            .ledger
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .locked()
            .unwrap(),
        before
            .channel_state
            .as_ref()
            .unwrap()
            .book
            .locked()
            .unwrap()
    );
    drop(node);
    cleanup(&root);
}

#[test]
fn native_channel_conflict_remote_return_fees_child_capacity_and_contact_authenticate() {
    let (root, mut earth, proof) = setup();
    let p = channel_integration::package(c::SEGMENTED_RULES);
    let region = p.admissions[1].id().unwrap();
    let mut remote =
        Store::create(&root.join("proxima"), p, region, &public(1), proof.currency).unwrap();
    let input = tagged(&earth, proof.channel, 10);
    let outgoing = export(&mut earth, input, region, 10, 11, 80);
    let frame = earth.contact_export(outgoing).unwrap();
    remote.contact_apply(&frame, Some(public(10))).unwrap();
    for _ in 0..2 {
        selected(&mut remote, vec![]);
    }
    snapshot(&mut remote);
    let import = tagged(&remote, proof.channel, 11);
    let returning = export(&mut remote, import, earth.chain.region, 11, 10, 40);
    earth
        .contact_apply(&remote.contact_export(returning).unwrap(), Some(public(10)))
        .unwrap();
    assert!(earth.chain.ledger.exports[&outgoing]
        .channel_dependencies
        .contains(&proof.channel));
    assert!(remote.chain.ledger.exports[&returning]
        .channel_dependencies
        .contains(&proof.channel));
    for c in remote.chain.ledger.coins.values() {
        assert!(c.channel_dependencies.contains(&proof.channel));
    }
    let child_input = tagged(&remote, proof.channel, 11);
    let remaining = remote.chain.ledger.coins[&child_input]
        .payment
        .amount
        .checked_sub(Amount(11))
        .unwrap();
    let open = command(
        &remote.chain,
        &remote.trust,
        c::Action::Open {
            witness: Some(public(12)),
            inputs: vec![child_input],
            parties: parties(),
            capacity: Amount(10),
            initial: [Amount(10), Amount::ZERO],
            change: vec![Payment {
                owner: public(11),
                amount: remaining,
            }],
            fee: Amount(1),
        },
        Some(11),
        &[10, 11],
    );
    let Command::Channel(ref n) = open else {
        panic!()
    };
    let child = n.action.intent.id().unwrap();
    selected(&mut remote, vec![open]);
    assert!(remote
        .chain
        .ledger
        .channel_state
        .as_ref()
        .unwrap()
        .book
        .channels[&child]
        .channel_dependencies
        .contains(&proof.channel));
    let before = conservation_with_escrow(&[earth.chain.clone(), remote.chain.clone()]).unwrap();
    earth.observe_conflict(proof.clone()).unwrap();
    let notice = earth.contact_export(outgoing).unwrap();
    let (_, mut bundle) = contact::Frame::unpack(&notice).unwrap();
    let conflict::Incident::Channel(ref mut p) = bundle.incidents[0] else {
        panic!()
    };
    p.right.approvals[0].signature = "00".into();
    let head = history::manifest(&root.join("proxima"))
        .unwrap()
        .head()
        .unwrap();
    assert!(remote
        .contact_apply(&contact::Frame::pack(&bundle).unwrap(), None)
        .is_err());
    assert!(remote.conflicts.is_empty());
    assert_eq!(
        head,
        history::manifest(&root.join("proxima"))
            .unwrap()
            .head()
            .unwrap()
    );
    let _ = remote.contact_apply(&notice, None);
    assert_eq!(remote.conflicts.len(), 1);
    let exposure = remote
        .safety
        .exposure(&remote.chain, &remote.evidence)
        .unwrap();
    assert_eq!(exposure.retained_channel_capacity, Amount(10));
    assert_eq!(exposure.quarantined_channels, vec![child]);
    assert_eq!(
        exposure.quarantined_coins.len(),
        remote.chain.ledger.coins.len()
    );
    assert!(exposure.affected_historical_exports.contains(&returning));
    assert_eq!(
        before,
        conservation_with_escrow(&[earth.chain.clone(), remote.chain.clone()]).unwrap()
    );
    let held = tagged(&remote, proof.channel, 11);
    let signed = intent(
        &remote.chain,
        &remote.trust,
        vec![held],
        vec![remote.chain.ledger.coins[&held].payment.clone()],
        None,
        None,
        0,
        0,
        &[11],
    );
    assert!(remote
        .template(vec![Command::Spend(Box::new(signed))], public(10))
        .is_err());
    let expected = history::manifest(&root.join("proxima"))
        .unwrap()
        .head()
        .unwrap();
    let retained = remote.chain.ledger.clone();
    drop(remote);
    assert!(Store::open_pinned(&root.join("proxima"), &public(1), proof.currency, head).is_err());
    let remote =
        Store::open_pinned(&root.join("proxima"), &public(1), proof.currency, expected).unwrap();
    assert_eq!(retained, remote.chain.ledger);
    assert!(remote.safety.channels.contains_key(&proof.channel));
    drop(remote);
    drop(earth);
    cleanup(&root);
}

#[test]
fn native_channel_conflict_cold_corruption_exact_recovery_retains_liabilities() {
    let (root, mut node, proof) = setup();
    let before = node.chain.ledger.clone();
    let old = history::manifest(&root.join("earth"))
        .unwrap()
        .head()
        .unwrap();
    let iid = node.observe_conflict(proof.clone()).unwrap();
    let head = history::manifest(&root.join("earth"))
        .unwrap()
        .head()
        .unwrap();
    drop(node);
    assert!(Store::open_pinned(&root.join("earth"), &public(1), proof.currency, old).is_err());
    let node = Store::open_pinned(&root.join("earth"), &public(1), proof.currency, head).unwrap();
    assert_eq!(node.chain.ledger, before);
    assert!(node.safety.channels.contains_key(&proof.channel));
    drop(node);
    let file = root
        .join("earth/incidents")
        .join(format!("{}.json", iid.to_hex()));
    fs::write(&file, b"{broken-complete-proof").unwrap();
    assert!(Store::open_pinned(&root.join("earth"), &public(1), proof.currency, head).is_err());
    let mut invalid = proof.clone();
    invalid.right.approvals[0].signature = "00".into();
    assert!(
        storage::recover_incident(&root.join("earth"), &public(1), proof.currency, invalid)
            .is_err()
    );
    storage::recover_incident(
        &root.join("earth"),
        &public(1),
        proof.currency,
        proof.clone(),
    )
    .unwrap();
    assert_eq!(
        fs::read(
            root.join("earth")
                .join(format!("damaged-incident-{}.bin", iid.to_hex()))
        )
        .unwrap(),
        b"{broken-complete-proof"
    );
    let node = Store::open(&root.join("earth"), &public(1), proof.currency).unwrap();
    assert_eq!(node.chain.ledger, before);
    assert!(node.safety.channels.contains_key(&proof.channel));
    let restored_head = history::manifest(&root.join("earth"))
        .unwrap()
        .head()
        .unwrap();
    drop(node);
    let image = root.join("image");
    let target = root.join("restored");
    let sealed = history_archive::seal(
        &root.join("earth"),
        &image,
        &public(1),
        proof.currency,
        restored_head,
    )
    .unwrap();
    assert!(sealed.files.keys().any(|p| p.starts_with("incidents/")));
    assert!(!sealed
        .files
        .keys()
        .any(|p| p.contains("wallet") || p.contains("signer") || p.contains("key")));
    assert!(history_archive::restore(&image, &target, &public(1), proof.currency, old).is_err());
    assert!(!target.exists());
    history_archive::restore(&image, &target, &public(1), proof.currency, restored_head).unwrap();
    let restored = Store::open_pinned(&target, &public(1), proof.currency, restored_head).unwrap();
    assert_eq!(restored.chain.ledger, before);
    assert!(restored.safety.channels.contains_key(&proof.channel));
    drop(restored);
    cleanup(&root);
}

#[test]
fn native_channel_conflict_combined_capacity_guard_preserves_all_sixteen_notices() {
    let (root, mut node, proof) = setup();
    let before = node.chain.ledger.clone();
    let mut fork = Chain::new(node.chain.region, &node.trust).unwrap();
    let empty = VerifiedEvidence::default();
    for _ in 0..node.chain.height() {
        let mut block = fork
            .template(vec![], public(13), &node.trust, &empty)
            .unwrap();
        mine(&mut block).unwrap();
        fork.accept(block, &node.trust, &empty).unwrap();
    }
    let region_fault = conflict::Conflict::from_snapshots(
        node.evidence.snapshot(proof.anchor).unwrap(),
        &checkpoint(&fork, &node.trust),
    )
    .unwrap();
    node.observe_conflict(region_fault).unwrap();
    for sequence in 1..conflict::MAX_INCIDENTS as u64 {
        let pair = channel_conflict::Conflict::canonical(
            proof.currency,
            proof.region,
            proof.channel,
            proof.anchor,
            proof.funding.clone(),
            signed_state(
                &node.chain,
                &node.trust,
                proof.channel,
                sequence,
                [Amount(30), Amount(30)],
            ),
            signed_state(
                &node.chain,
                &node.trust,
                proof.channel,
                sequence,
                [Amount(40), Amount(20)],
            ),
        )
        .unwrap();
        node.observe_conflict(pair).unwrap();
    }
    assert_eq!(node.conflicts.len(), 16);
    let retained: BTreeMap<_, _> = fs::read_dir(root.join("earth/incidents"))
        .unwrap()
        .map(|p| {
            let p = p.unwrap().path();
            (p.file_name().unwrap().to_owned(), fs::read(p).unwrap())
        })
        .collect();
    assert_eq!(retained.len(), 16);
    let overflow = channel_conflict::Conflict::canonical(
        proof.currency,
        proof.region,
        proof.channel,
        proof.anchor,
        proof.funding.clone(),
        signed_state(
            &node.chain,
            &node.trust,
            proof.channel,
            17,
            [Amount(30), Amount(30)],
        ),
        signed_state(
            &node.chain,
            &node.trust,
            proof.channel,
            17,
            [Amount(40), Amount(20)],
        ),
    )
    .unwrap();
    assert!(node.observe_conflict(overflow.clone()).is_err());
    assert_eq!(node.chain.ledger, before);
    assert_eq!(node.conflicts.len(), 16);
    assert_eq!(
        fs::read(root.join("earth/INCIDENT_GUARD")).unwrap(),
        overflow.id().unwrap().0
    );
    for (name, raw) in retained {
        assert_eq!(
            fs::read(root.join("earth/incidents").join(name)).unwrap(),
            raw
        );
    }
    drop(node);
    assert!(Store::open(&root.join("earth"), &public(1), proof.currency).is_err());
    assert_eq!(
        fs::read_dir(root.join("earth/incidents")).unwrap().count(),
        16
    );
    cleanup(&root);
}
