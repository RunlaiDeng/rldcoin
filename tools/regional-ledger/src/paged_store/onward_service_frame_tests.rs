//! Fresh complete Native ancestry exercises typed carriage, not Service scheduling.
use super::*;
use crate::contact::{Frame, MAX_FRAME, MAX_PAYLOAD};

fn rebind(mut frame: Frame, payload: Option<&[u8]>) -> Vec<u8> {
    if let Some(payload) = payload {
        frame.payload_sha256 = sha(payload);
        frame.payload_b64 = STANDARD.encode(payload);
    }
    frame.message_id = frame.message().unwrap();
    frame.retained_bytes().unwrap()
}
fn inspect(raw: &[u8]) -> Result<(Frame, Vec<u8>)> {
    crate::contact_frame::inspect_bytes(raw, None, None, MAX_PAYLOAD, MAX_FRAME)
}
fn unchanged_refusal(root: &Path, node: &mut Store, proof: CompleteOnwardNetworkHistory) {
    let before = inventory(root);
    let head = node.storage_head().unwrap();
    let chain = node.chain.clone();
    assert!(node.accept_complete_onward_network_history(proof).is_err());
    assert_eq!(node.storage_head().unwrap(), head);
    assert_eq!(node.chain.ledger, chain.ledger);
    assert_eq!(node.chain.finalized, chain.finalized);
    assert_eq!(node.chain.height(), chain.height());
    assert_eq!(node.chain.tip().unwrap(), chain.tip().unwrap());
    assert!(node.journal.incident_ids.is_empty());
    assert_eq!(inventory(root), before);
}
fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original60 complete onward carriage guard exhausted"
    );
}

#[test]
#[ignore = "fresh complete A80/B4 Native carriage, domain and canonical-boundary controls"]
fn complete_onward_carriage_preserves_native_proof_and_refuses_domain_confusion() {
    let started = now();
    let deadline = started + 60.0;
    let (root, bootstrap, proof, a80, b4, export) = ancestors();
    check(deadline);
    let currency = bootstrap.currency.id().unwrap();
    let source = Store::open(&root.join("intermediate"), &public(1), currency).unwrap();
    let mut receiver = Store::create(
        &root.join("carriage-receiver"),
        bootstrap.clone(),
        proof.history.destination,
        &public(1),
        currency,
    )
    .unwrap();
    let before = inventory(&root);
    let source_head = source.storage_head().unwrap();
    let source_ledger = source.chain.ledger.clone();
    let receiver_head = receiver.storage_head().unwrap();
    let raw = source.contact_export(export).unwrap();
    assert_eq!(raw, Frame::pack_onward(&proof).unwrap());
    assert_eq!(raw, source.contact_export(export).unwrap());
    let (frame, decoded) = Frame::unpack_onward(&raw).unwrap();
    assert_eq!(decoded, proof);
    assert_eq!(frame.kind, "onward-source-finality");
    assert_eq!(frame.source_chain_id, proof.history.source);
    assert_eq!(frame.destination_chain_id, receiver.chain.region);
    assert_eq!(frame.export_id, export);
    assert_eq!(source.chain.height(), 5); // The actual earliest export remains B4.
    assert_eq!(decoded.history.snapshots.len(), 4);
    assert_eq!(decoded.history.snapshots[3].statement.id().unwrap(), b4);
    assert_eq!(decoded.history.origin.snapshots.len(), 80);
    assert_eq!(
        decoded.history.origin.snapshots[79].statement.id().unwrap(),
        a80
    );
    let anchors = decoded
        .verify_anchors(receiver.chain.region, &receiver.trust)
        .unwrap();
    assert!(anchors.snapshots.contains_key(&a80) && anchors.snapshots.contains_key(&b4));
    let (opaque, payload) = inspect(&raw).unwrap();
    assert_eq!(opaque.message_id, frame.message_id);
    assert_eq!(sha(&payload), frame.payload_sha256);
    assert_eq!(payload, files::canonical(&proof).unwrap());
    assert!(Frame::unpack(&raw).is_err());
    assert!(Frame::unpack_origin(&raw).is_err());
    assert!(
        crate::paged_bft::require_runtime_adoption(crate::paged_bft::ONWARD_NETWORK_RULES).is_err()
    );
    assert!(receiver.contact_apply(&raw, None).is_err());

    // Every malformed outer mutation gets a new valid message hash where
    // relevant, so refusal checks the named binding rather than stale identity.
    for name in ["source", "destination", "export"] {
        let mut altered = frame.clone();
        match name {
            "source" => altered.source_chain_id = proof.history.origin.source,
            "destination" => altered.destination_chain_id = proof.history.origin.source,
            "export" => altered.export_id = proof.history.origin.export,
            _ => unreachable!(),
        }
        assert!(Frame::unpack_onward(&rebind(altered, None)).is_err());
    }
    let mut old_kind = frame.clone();
    old_kind.kind = "source-finality".into();
    let old_kind = rebind(old_kind, None);
    assert!(Frame::unpack_onward(&old_kind).is_err());
    assert!(Frame::unpack_origin(&old_kind).is_err());
    let old_origin = Frame::origin_frame(&proof.history.origin).unwrap();
    let old_raw = old_origin.retained_bytes().unwrap();
    assert_eq!(
        Frame::unpack_origin(&old_raw).unwrap().1,
        proof.history.origin
    );
    let mut wrong_new_kind = old_origin;
    wrong_new_kind.kind = "onward-source-finality".into();
    assert!(Frame::unpack_onward(&rebind(wrong_new_kind, None)).is_err());
    let mut noncanonical_outer = b" ".to_vec();
    noncanonical_outer.extend_from_slice(&raw);
    assert!(Frame::unpack_onward(&noncanonical_outer).is_err());
    let mut noncanonical_payload = b" ".to_vec();
    noncanonical_payload.extend_from_slice(&payload);
    assert!(Frame::unpack_onward(&rebind(frame.clone(), Some(&noncanonical_payload))).is_err());
    let mut unknown = serde_json::to_value(&proof).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), json!(true));
    assert!(Frame::unpack_onward(&rebind(
        frame.clone(),
        Some(&files::canonical(&unknown).unwrap())
    ))
    .is_err());
    let history = files::canonical(&serde_json::to_value(&proof.history).unwrap()).unwrap();
    let duplicate = format!(
        "{{\"history\":{},\"history\":{}}}",
        String::from_utf8(history.clone()).unwrap(),
        String::from_utf8(history).unwrap()
    );
    assert!(Frame::unpack_onward(&rebind(frame.clone(), Some(duplicate.as_bytes()))).is_err());
    let mut changed_hash = frame.clone();
    changed_hash.payload_sha256 = Hash::ZERO;
    assert!(Frame::unpack_onward(&rebind(changed_hash, None)).is_err());
    let mut changed_message = frame.clone();
    changed_message.message_id = Hash::ZERO;
    assert!(Frame::unpack_onward(&changed_message.retained_bytes().unwrap()).is_err());
    let oversized = vec![b'x'; MAX_PAYLOAD + 1];
    let oversized = rebind(frame.clone(), Some(&oversized));
    assert!(oversized.len() <= MAX_FRAME);
    assert!(Frame::unpack_onward(&oversized).is_err());
    assert!(inspect(&oversized).is_err());
    assert!(Frame::unpack_onward(&vec![b'x'; MAX_FRAME + 1]).is_err());
    check(deadline);

    // Opaque transit and typed decoding do not partially authorize a currency or
    // inspect a prefix. The actual Native API is the full-proof refusal boundary.
    let mut wrong_currency = proof.clone();
    wrong_currency.history.origin.snapshots[0]
        .statement
        .currency = Hash::ZERO;
    let altered = Frame::pack_onward(&wrong_currency).unwrap();
    assert!(inspect(&altered).is_ok());
    let (_, altered) = Frame::unpack_onward(&altered).unwrap();
    unchanged_refusal(&root, &mut receiver, altered);
    let mut missing_a = proof.clone();
    missing_a.history.origin.snapshots.clear();
    let (_, missing_a) = Frame::unpack_onward(&Frame::pack_onward(&missing_a).unwrap()).unwrap();
    unchanged_refusal(&root, &mut receiver, missing_a);
    let mut missing_b_tail = proof.clone();
    missing_b_tail.history.snapshots.pop();
    let (_, missing_b_tail) =
        Frame::unpack_onward(&Frame::pack_onward(&missing_b_tail).unwrap()).unwrap();
    unchanged_refusal(&root, &mut receiver, missing_b_tail);
    assert_eq!(source.storage_head().unwrap(), source_head);
    assert_eq!(source.chain.ledger, source_ledger);
    assert_eq!(receiver.storage_head().unwrap(), receiver_head);
    assert_eq!(receiver.chain.height(), 0);
    assert_eq!(receiver.chain.ledger, Ledger::default());
    assert_eq!(inventory(&root), before);
    check(deadline);

    // Genuine fully signed competing A80 must be retained even with a later
    // invalid B record. Forging that same A signature cannot manufacture an incident.
    assert_eq!(
        receiver
            .accept_complete_onward_network_history(proof.clone())
            .unwrap(),
        b4
    );
    assert_eq!(receiver.chain.ledger, Ledger::default());
    assert_eq!(
        receiver.complete_onward_network_pending_imports().unwrap(),
        vec![Command::Import {
            snapshot: b4,
            export
        }]
    );
    let alternate = super::negative_seams::authentic_alternate_a80(&bootstrap, &proof);
    let mut conflicted = proof.clone();
    conflicted.history.origin.snapshots[79] = alternate;
    let mut invalid_later = conflicted.history.snapshots[3].clone();
    invalid_later.bft.as_mut().unwrap().committed.votes[0]
        .approval
        .signature = "00".repeat(64);
    conflicted.history.snapshots.push(invalid_later);
    let mut forged = conflicted.clone();
    forged.history.origin.snapshots[79]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    let forged = Frame::pack_onward(&forged).unwrap();
    assert!(inspect(&forged).is_ok());
    let (_, forged) = Frame::unpack_onward(&forged).unwrap();
    unchanged_refusal(&root, &mut receiver, forged);
    let conflicted = Frame::pack_onward(&conflicted).unwrap();
    assert!(inspect(&conflicted).is_ok());
    let (_, conflicted) = Frame::unpack_onward(&conflicted).unwrap();
    let ledger = receiver.chain.ledger.clone();
    let error = receiver
        .accept_complete_onward_network_history(conflicted)
        .unwrap_err();
    assert!(error.contains("conflict retained"), "{error}");
    assert_eq!(receiver.journal.incident_ids.len(), 1);
    assert!(receiver
        .safety
        .check_region(proof.history.origin.source)
        .is_err());
    assert_eq!(receiver.chain.height(), 0);
    assert_eq!(receiver.chain.ledger, ledger);
    let quarantined = inventory(&root);
    assert!(receiver
        .accept_complete_onward_network_history(proof.clone())
        .is_err());
    assert!(receiver.complete_onward_network_pending_imports().is_err());
    assert_eq!(inventory(&root), quarantined);
    assert_eq!(source.storage_head().unwrap(), source_head);
    assert_eq!(source.chain.ledger, source_ledger);
    check(deadline);
    eprintln!(
        "\nonward_service_carriage_result={}",
        json!({
            "root":root,"passed":true,"elapsed_seconds":now()-started,
            "real_a80_b4_proof":true,"later_b5_preserves_earliest_export":true,
            "exact_frame_native_binding":true,"opaque_is_not_currency_authority":true,
            "old_kind_domain_isolation":true,"canonical_payload_shape_and_bounds":true,
            "actual_native_bad_currency_and_missing_history_refused":true,
            "canonical_and_forged_refusals_inventory_unchanged":true,
            "valid_native_custody_without_credit":true,"genuine_conflict_before_bad_tail":true,
            "forged_no_incident":true,"current_quarantine_refuses_retry":true,"no_credit":true,
            "ordinary_service":false,"owner_payment_qualified":false,
            "fresh_process_cold":false,"independent_qualification":false
        })
    );
}
