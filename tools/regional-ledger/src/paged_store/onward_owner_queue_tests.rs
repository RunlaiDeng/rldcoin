//! Independent fresh refusal component. C certificates here use the existing
//! public fixture certificate factory; they are NOT original Runtime consensus
//! evidence. The positive C0-to-C5 runner never calls this module.
use super::negative_seams::Target;
use super::*;
use crate::{bft_runtime_envelope::Wire, wallet, wallet_agent};

const SHAPE: &str = "onward owner queue requires one to four local Spend commands";
const MISSING: &str = "onward cold complete material absent from Native history";
fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 60-second owner queue negative scope exhausted"
    );
}
// Negative-only fixture certificates. Every certificate is still authenticated
// by the actual Native finalize path; this is not an Agent scheduling test.
fn fixture_certificate(node: &mut Store, commands: Vec<Command>) -> Snapshot {
    let snapshot = certified_with_commands(&node.paged_replay.as_ref().unwrap().replay, commands);
    node.finalize(snapshot.clone()).unwrap();
    snapshot
}
// Same certified B4 statement with a different real ordered 3-of-4 quorum.
// This changes full wrapper identity without changing any selected checkpoint.
pub(super) fn authentic_wrapper_variant(
    proof: &CompleteOnwardNetworkHistory,
) -> CompleteOnwardNetworkHistory {
    let mut variant = proof.clone();
    let certificate = variant
        .history
        .snapshots
        .last_mut()
        .unwrap()
        .bft
        .as_mut()
        .unwrap();
    for quorum in [&mut certificate.prepared, &mut certificate.committed] {
        assert_eq!(quorum.votes.len(), 3);
        let seed = (2u8..6)
            .find(|seed| {
                !quorum
                    .votes
                    .iter()
                    .any(|vote| vote.approval.key == public(*seed))
            })
            .unwrap();
        let mut vote = quorum.votes[2].clone();
        vote.approval.key = public(seed);
        vote.approval.signature = signature(seed, &vote.bytes().unwrap());
        quorum.votes[2] = vote;
        quorum
            .votes
            .sort_by(|a, b| a.approval.key.cmp(&b.approval.key));
    }
    assert_ne!(&variant, proof);
    assert_eq!(
        variant.history.snapshots.last().unwrap().statement,
        proof.history.snapshots.last().unwrap().statement
    );
    variant
}
fn owner_client(root: &Path, node: &Store) -> files::Client {
    files::Client::lock(
        &root.join("owner-caller"),
        &root.join("owner-wallet"),
        public(12),
        node,
    )
    .unwrap()
}
fn create_owner(target: &Target) -> Hash {
    let agent =
        wallet_agent::Agent::create(&target.root.join("owner-wallet"), &target.node, public(12))
            .unwrap();
    assert_eq!(agent.journal.creation.pin.height, 0);
    assert!(agent.journal.records.is_empty());
    let head = agent.journal.head().unwrap();
    drop(agent);
    dir(&target.root.join("owner-caller"));
    let caller = owner_client(&target.root, &target.node)
        .open(&target.node, Some(head))
        .unwrap();
    assert_eq!(caller.head, Some(head));
    assert!(caller.pending.is_none());
    new_json(
        &target.root.join("owner-key.json"),
        &json!({"secret_key":hex::encode([12u8;32])}),
    );
    head
}
fn sign_owner(target: &Target, export: Hash, head: Hash) -> Vec<Command> {
    let node = &target.node;
    assert_eq!(node.chain.height(), 4);
    let mut agent = wallet_agent::Agent::open(&target.root.join("owner-wallet"), node).unwrap();
    let prepared = agent
        .prepare(
            node,
            wallet::Request {
                owner: public(12),
                participants: vec![],
                inputs: Some(vec![id("output", &(export, 0u32)).unwrap()]),
                outputs: vec![Payment {
                    owner: public(13),
                    amount: Amount(88),
                }],
                remote: None,
                fee: Amount(1),
                valid_for_blocks: 8,
                valid_through: None,
            },
            head,
        )
        .unwrap();
    assert_eq!(prepared.draft.selected_input_total, Amount(89));
    assert_eq!(prepared.draft.change, Amount::ZERO);
    drop(agent);
    let caller = owner_client(&target.root, node);
    let previous = caller.read().unwrap();
    let mut proposed = previous.clone();
    proposed.pending = Some(files::Pending {
        prepared: prepared.clone(),
    });
    let pending = caller
        .store(node, files::Transition { previous, proposed })
        .unwrap();
    drop(caller);
    agent = wallet_agent::Agent::open(&target.root.join("owner-wallet"), node).unwrap();
    let signed = agent
        .sign(
            node,
            prepared.draft,
            &target.root.join("owner-key.json"),
            prepared.review_commitment,
            head,
        )
        .unwrap();
    assert!(!signed.recovered_exact_retry && signed.retained_approvals_complete);
    assert_eq!(agent.journal.records.len(), 1);
    assert_eq!(
        agent
            .view(node, signed.wallet_head)
            .unwrap()
            .reserved_owned_outputs,
        Amount(89)
    );
    drop(agent);
    let caller = owner_client(&target.root, node);
    assert_eq!(caller.read().unwrap(), pending);
    let mut proposed = pending.clone();
    proposed.head = Some(signed.wallet_head);
    proposed.pending = None;
    let published = caller
        .store(
            node,
            files::Transition {
                previous: pending,
                proposed,
            },
        )
        .unwrap();
    assert_eq!(published.head, Some(signed.wallet_head));
    assert!(published.pending.is_none());
    signed.commands
}
fn direct_refusal(target: &Target, commands: Vec<Command>, expected: &str) {
    let before = inventory(&target.root);
    let head = target.node.storage_head().unwrap();
    let ledger = target.node.chain.ledger.clone();
    assert_eq!(target.node.bft_submit(commands).unwrap_err(), expected);
    assert_eq!(target.node.storage_head().unwrap(), head);
    assert_eq!(target.node.chain.ledger, ledger);
    assert_eq!(inventory(&target.root), before);
}
fn install(target: &mut Target, proof: &CompleteOnwardNetworkHistory, snapshots: &[Snapshot]) {
    target
        .node
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    for snapshot in snapshots {
        target
            .node
            .finalize_onward_network_certificate(snapshot.clone())
            .unwrap();
    }
    target
        .node
        .require_retained_onward_material(Some(proof), snapshots)
        .unwrap();
}
fn queue_refusal(mut target: Target, filename: Hash, raw: &[u8], expected: &str, deadline: f64) {
    check(deadline);
    let queue = dir(&target.node.directory().join("bft-submissions"));
    crate::keystore::private_create(&queue.join(format!("{}.json", filename.to_hex())), raw)
        .unwrap();
    let before = inventory(&target.root);
    let head = target.node.storage_head().unwrap();
    let ledger = target.node.chain.ledger.clone();
    let caller = fs::read(target.root.join("caller-0/head.json")).unwrap();
    let archive = fs::read(target.root.join("runtime-0/state.json")).unwrap();
    let error = target
        .actor
        .as_mut()
        .unwrap()
        .tick(&mut target.node)
        .unwrap_err();
    assert_eq!(error, expected);
    assert_eq!(target.node.storage_head().unwrap(), head);
    assert_eq!(target.node.chain.ledger, ledger);
    assert_eq!(
        fs::read(target.root.join("caller-0/head.json")).unwrap(),
        caller
    );
    assert_eq!(
        fs::read(target.root.join("runtime-0/state.json")).unwrap(),
        archive
    );
    assert_eq!(
        inventory(&target.root),
        before,
        "queue refusal changed retained state"
    );
    target.stop();
    check(deadline);
    eprintln!(
        "onward_owner_queue_refusal={}",
        json!({"target":target.root.file_name().unwrap().to_string_lossy(),"error":error,"unchanged":true})
    );
    // Do not repair, remove or reopen any refused queue target.
}
// These are narrow tests of the extracted original writer, not synthetic
// authorized commands. Neither helper call claims Native owner admission.
fn retained_writer_bounds(root: &Path, bootstrap: &Bootstrap, region: Hash, deadline: f64) {
    for capacity in [false, true] {
        check(deadline);
        let path = dir(&root.join(if capacity {
            "writer-capacity"
        } else {
            "writer-collision"
        }));
        let node = Store::create(
            &path.join("ledger"),
            bootstrap.clone(),
            region,
            &public(1),
            bootstrap.currency.id().unwrap(),
        )
        .unwrap();
        let queue = dir(&node.directory().join("bft-submissions"));
        let ident = id("owner-queue-writer-bound-fixture", &capacity).unwrap();
        if capacity {
            for n in 0..32 {
                crate::keystore::private_create(
                    &queue.join(format!("retained-{n:02}.json")),
                    b"retained residue",
                )
                .unwrap();
            }
        } else {
            crate::keystore::private_create(
                &queue.join(format!("{}.json", ident.to_hex())),
                b"original bytes",
            )
            .unwrap();
            let before = inventory(&path);
            assert_eq!(
                node.write_bft_submission(ident, || Ok(b"original bytes".to_vec()))
                    .unwrap(),
                ident
            );
            assert_eq!(inventory(&path), before);
        }
        let before = inventory(&path);
        let head = node.storage_head().unwrap();
        let expected = if capacity {
            "BFT submission capacity; retain all previous commands"
        } else {
            "BFT submission filename collision"
        };
        assert_eq!(
            node.write_bft_submission(ident, || Ok(b"different bytes".to_vec()))
                .unwrap_err(),
            expected
        );
        assert_eq!(node.storage_head().unwrap(), head);
        assert_eq!(inventory(&path), before);
        check(deadline);
    }
}

#[test]
#[ignore = "fresh signed complete-history owner queue refusal component; original 60-second scope"]
fn onward_owner_queue_authenticates_material_and_refuses_unsafe_inputs() {
    let started = now();
    let deadline = started + 60.0;
    let (root, bootstrap, proof, _a80, b4, export) = ancestors();
    check(deadline);
    let c = proof.history.destination;
    let mut source = Target::new(&root, "queue-signed-source", &bootstrap, c);
    let owner_head = create_owner(&source);
    fixture_certificate(&mut source.node, vec![]);
    source
        .node
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    let imports = source
        .node
        .complete_onward_network_pending_imports()
        .unwrap();
    assert_eq!(
        imports,
        vec![Command::Import {
            snapshot: b4,
            export
        }]
    );
    // General explicit incoming Submission(Import) remains valid. Only the new
    // local owner queue rejects it; no local credit follows either pure check.
    let import_wire = net::local_envelope(Body::Submission(imports.clone()), &source.node).unwrap();
    let import_envelope = import_wire.clone().expand().unwrap();
    let before = inventory(&source.root);
    let import_id = import_envelope.verify(&source.node).unwrap();
    assert_eq!(inventory(&source.root), before);
    direct_refusal(&source, imports.clone(), SHAPE);
    fixture_certificate(&mut source.node, imports);
    fixture_certificate(&mut source.node, vec![]);
    fixture_certificate(&mut source.node, vec![]);
    let commands = sign_owner(&source, export, owner_head);
    let wire = net::local_envelope(Body::Submission(commands.clone()), &source.node).unwrap();
    let envelope = wire.clone().expand().unwrap();
    let ident = envelope.verify(&source.node).unwrap();
    let snapshots = &envelope.evidence.snapshots;
    assert_eq!(snapshots.len(), 4);
    assert_eq!(snapshots.last().unwrap().statement.height, 4);
    assert_eq!(envelope.history.as_ref().unwrap(), &proof);
    source
        .node
        .require_retained_onward_material(Some(&proof), snapshots)
        .unwrap();
    source
        .node
        .bft_candidate(
            commands.clone(),
            source.node.trust.region(c).unwrap().validators[0].clone(),
        )
        .unwrap();
    let raw = serde_json::to_vec(&wire).unwrap();
    assert_ne!(ident, sha(&files::canonical(&envelope.body).unwrap()));
    direct_refusal(&source, vec![], SHAPE);
    direct_refusal(&source, vec![commands[0].clone(); 5], SHAPE);
    let mut remote_shape = commands.clone();
    let Command::Spend(remote) = &mut remote_shape[0] else {
        panic!("actual owner Spend")
    };
    remote.intent.destination_fee = Amount(1);
    direct_refusal(&source, remote_shape, SHAPE);
    let mut invalid = envelope.clone();
    let Body::Submission(bad_commands) = &mut invalid.body else {
        unreachable!()
    };
    let Command::Spend(bad) = &mut bad_commands[0] else {
        unreachable!()
    };
    let mut signature = hex::decode(&bad.approvals[0].signature).unwrap();
    signature[0] ^= 1;
    bad.approvals[0].signature = hex::encode(signature);
    let signature_error = crate::verification_keys::verify_bytes(
        &bad.approvals[0].key,
        &bad.intent.bytes().unwrap(),
        &bad.approvals[0].signature,
    )
    .unwrap_err();
    let invalid_commands = bad_commands.clone();
    assert_eq!(invalid.verify(&source.node).unwrap_err(), signature_error);
    direct_refusal(&source, invalid_commands, &signature_error);
    assert!(!source.node.directory().join("bft-submissions").exists());
    check(deadline);

    let variant = authentic_wrapper_variant(&proof);
    let mut uninstalled_wrapper = envelope.clone();
    uninstalled_wrapper.history = Some(variant.clone());
    let variant_id = uninstalled_wrapper.verify(&source.node).unwrap();
    assert_ne!(variant_id, ident);
    source
        .node
        .require_retained_onward_material(None, snapshots)
        .unwrap();
    assert_eq!(
        source
            .node
            .require_retained_onward_material(Some(&variant), snapshots)
            .unwrap_err(),
        MISSING
    );
    new_json(
        &source.root.join("original-wrapper-before-variant.json"),
        &proof,
    );
    new_json(
        &source.root.join("authentic-uninstalled-wrapper.json"),
        &variant,
    );
    let variant_raw = serde_json::to_vec(&uninstalled_wrapper.pack().unwrap()).unwrap();
    queue_refusal(source, variant_id, &variant_raw, MISSING, deadline);

    let mut parent = Target::new(&root, "queue-uninstalled-parent", &bootstrap, c);
    install(&mut parent, &proof, &snapshots[..3]);
    assert_eq!(parent.node.chain.height(), 3);
    assert_eq!(envelope.verify(&parent.node).unwrap(), ident);
    assert_eq!(
        parent
            .node
            .require_retained_onward_material(Some(&proof), snapshots)
            .unwrap_err(),
        MISSING
    );
    queue_refusal(parent, ident, &raw, MISSING, deadline);

    let mut filename = Target::new(&root, "queue-wrong-filename", &bootstrap, c);
    install(&mut filename, &proof, snapshots);
    assert_eq!(envelope.verify(&filename.node).unwrap(), ident);
    let wrong_name = id("deliberately-wrong-owner-queue-filename", &ident).unwrap();
    assert_ne!(wrong_name, ident);
    queue_refusal(
        filename,
        wrong_name,
        &raw,
        "BFT submission filename binding",
        deadline,
    );

    let bad_owner = Target::new(&root, "queue-invalid-owner-signature", &bootstrap, c);
    assert_eq!(envelope.verify(&bad_owner.node).unwrap(), ident);
    assert_eq!(
        invalid.verify(&bad_owner.node).unwrap_err(),
        signature_error
    );
    let bad_id = id("complete-onward-network-envelope-v1", &invalid).unwrap();
    let bad_raw = serde_json::to_vec(&invalid.pack().unwrap()).unwrap();
    queue_refusal(bad_owner, bad_id, &bad_raw, &signature_error, deadline);

    let wrong_format = Target::new(&root, "queue-wrong-format", &bootstrap, c);
    let mut value = serde_json::to_value(&wire).unwrap();
    value["format"] = json!(crate::bft_network::FORMAT);
    queue_refusal(
        wrong_format,
        ident,
        &serde_json::to_vec(&value).unwrap(),
        "onward Runtime envelope format/history differs",
        deadline,
    );
    let mut missing_history = serde_json::to_value(&wire).unwrap();
    missing_history.as_object_mut().unwrap().remove("history");
    assert!(
        matches!(Wire::bytes(&serde_json::to_vec(&missing_history).unwrap(), bft_client::ONWARD_FORMAT),
        Err(error) if error == "onward Runtime envelope format/history differs")
    );

    let shape = Target::new(&root, "queue-authentic-import-body", &bootstrap, c);
    assert_eq!(import_envelope.verify(&shape.node).unwrap(), import_id);
    queue_refusal(
        shape,
        import_id,
        &serde_json::to_vec(&import_wire).unwrap(),
        SHAPE,
        deadline,
    );
    retained_writer_bounds(&root, &bootstrap, c, deadline);
    check(deadline);
    eprintln!(
        "onward_owner_queue_negative_result={}",
        json!({"root":root,
        "elapsed_seconds":now()-started,"passed":true,"runtime_targets":6,
        "writer_only_targets":2,"c_certificates":"negative-only public fixture factory",
        "owner_signature":"original C0 Agent and separate caller consent",
        "general_import_submission_unchanged":true,"uninstalled_wrapper_and_parent_refused":true,
        "strict_format_filename_shape_signature":true,"retained_writer_bounds":true,
        "fresh_process_cold":false,"runtime_consensus":false,"ordinary_service":false,
        "independent_qualification":false})
    );
    // Entire fresh scope, including all refused inputs, remains for the seal.
}
