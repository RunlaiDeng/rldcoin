use super::*;
use crate::cold_plan::{self, Batch, Plan};
use sha2::{Digest, Sha256};

fn batch(root: &Path, wires: Vec<bft_network::WireEnvelope>) -> Batch {
    let raw = serde_json::to_vec(&wires).unwrap();
    let hash = Hash(Sha256::digest(&raw).into());
    fs::write(root.join(format!("{}.json", hash.to_hex())), &raw).unwrap();
    Batch {
        sha256: hash,
        bytes: raw.len(),
        envelopes: wires.len(),
    }
}
fn plan(h: &Harness, root: &Path, batches: Vec<Batch>) -> PathBuf {
    let path = root.join("plan.json");
    fs::write(
        &path,
        serde_json::to_vec(&Plan {
            format: cold_plan::FORMAT.into(),
            currency: h.node.trust.currency().unwrap(),
            region: h.node.chain.region,
            batches,
        })
        .unwrap(),
    )
    .unwrap();
    path
}
fn input(h: &Harness) -> PathBuf {
    let path = h.root.join("cold-input");
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn cold_plan_authenticates_repeated_complete_batches_and_preserves_custody() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let root = input(&h);
    let item = batch(&root, vec![wire.clone(); 4]);
    let file = plan(&h, &root, vec![item.clone(); 2]);
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    let heads = h.heads.clone();
    let head = h.node.storage_head().unwrap();
    let checked = cold_plan::check(&file, &h.node, head).unwrap();
    assert_eq!(checked.batches.len(), 2);
    let id = wire.expand().unwrap().verify(&h.node).unwrap();
    for batch in checked.batches {
        assert_eq!(batch.results.len(), 4);
        for row in batch.results {
            assert_eq!(row.message_id, id);
        }
    }
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
    assert_eq!(heads, h.heads);
    assert!(cold_plan::check(&file, &h.node, Hash::ZERO).is_err());
    assert!(cold_plan::check(&file, &h.node, Hash([1; 32])).is_err());
}

#[test]
fn cold_plan_later_bad_signature_same_body_or_invalid_evidence_refuses_everything() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let root = input(&h);
    let good = batch(&root, vec![wire.clone()]);
    let before = fs::read(h.root.join("node/journal.json")).unwrap();
    let head = h.node.storage_head().unwrap();
    let heads = h.heads.clone();
    let mut bad = wire.clone();
    let bft_network::Body::Signed(message) = &mut bad.body else {
        panic!()
    };
    let Message::Proposal(proposal) = message.as_mut() else {
        panic!()
    };
    proposal.leader.signature = "00".repeat(64);
    let later = batch(&root, vec![bad]);
    let file = plan(&h, &root, vec![good.clone(), later]);
    assert!(cold_plan::check(&file, &h.node, head)
        .unwrap_err()
        .contains("signature"));
    let mut missing = wire;
    missing
        .evidence
        .snapshots
        .push(crate::carriage::CarriedSnapshot {
            prefix: None,
            snapshot: h.node.bft_candidate(vec![], public(10)).unwrap(),
        });
    let later = batch(&root, vec![missing]);
    let file = plan(&h, &root, vec![good, later]);
    assert!(cold_plan::check(&file, &h.node, head).is_err());
    assert_eq!(before, fs::read(h.root.join("node/journal.json")).unwrap());
    assert_eq!(heads, h.heads);
}

#[test]
fn cold_plan_refuses_declaration_digest_domain_unknown_field_and_capacity() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let root = input(&h);
    let good = batch(&root, vec![wire]);
    let head = h.node.storage_head().unwrap();
    for batches in [
        vec![],
        vec![good.clone(); 513],
        vec![
            Batch {
                envelopes: 4,
                ..good.clone()
            };
            129
        ],
        vec![Batch {
            envelopes: 5,
            ..good.clone()
        }],
        vec![Batch {
            bytes: MAX_BYTES + 1,
            ..good.clone()
        }],
        vec![Batch {
            sha256: Hash::ZERO,
            ..good.clone()
        }],
        vec![Batch {
            bytes: good.bytes + 1,
            ..good.clone()
        }],
        vec![Batch {
            envelopes: 2,
            ..good.clone()
        }],
    ] {
        let file = plan(&h, &root, batches);
        assert!(cold_plan::check(&file, &h.node, head).is_err());
    }
    let file = plan(&h, &root, vec![good]);
    let raw = fs::read(&file).unwrap();
    for key in ["format", "currency", "region", "unknown"] {
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value[key] = serde_json::json!(if key == "format" {
            "wrong".into()
        } else {
            Hash::ZERO.to_hex()
        });
        fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(cold_plan::check(&file, &h.node, head).is_err());
    }
    let mut duplicate = raw[..raw.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"format\":\"bad\"}");
    fs::write(&file, duplicate).unwrap();
    assert!(cold_plan::check(&file, &h.node, head).is_err());
}

#[test]
fn cold_plan_refuses_unsafe_missing_altered_and_oversized_archives() {
    let mut h = Harness::new();
    let wire = cold_batch_envelope(&mut h);
    let root = input(&h);
    let good = batch(&root, vec![wire]);
    let file = plan(&h, &root, vec![good.clone()]);
    let head = h.node.storage_head().unwrap();
    let path = root.join(format!("{}.json", good.sha256.to_hex()));
    let raw = fs::read(&path).unwrap();
    fs::write(&path, b"[]").unwrap();
    assert!(cold_plan::check(&file, &h.node, head).is_err());
    fs::remove_file(&path).unwrap();
    assert!(cold_plan::check(&file, &h.node, head).is_err());
    fs::write(&path, &raw).unwrap();
    #[cfg(unix)]
    {
        let link = root.join("unsafe-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(cold_plan::check(&file, &h.node, head).is_err());
        fs::remove_file(link).unwrap();
    }
    let extra = root.join("extra");
    fs::File::create(&extra)
        .unwrap()
        .set_len(MAX_BYTES as u64 + 1)
        .unwrap();
    assert!(cold_plan::check(&file, &h.node, head).is_err());
    fs::remove_file(extra).unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    assert!(cold_plan::check(&file, &h.node, head).is_err());
}

#[test]
fn cold_plan_pinned_inspection_refuses_lock_stale_head_pending_and_unindexed_incidents() {
    for rules in [bft::RULES, crate::paged_bft::RULES] {
        let mut h = Harness::with_rules(rules);
        let path = h.root.join("node");
        let pin = h.node.trust.currency().unwrap();
        let head = h.node.storage_head().unwrap();
        assert!(Store::open_pinned_inspection(&path, &public(1), pin, head).is_err());
        h.retain = true;
        drop(h);
        assert!(Store::open_pinned_inspection(&path, &public(1), pin, Hash::ZERO).is_err());
        assert!(Store::open_pinned_inspection(&path, &public(1), pin, Hash([1; 32])).is_err());
        let reopened = Store::open_pinned_inspection(&path, &public(1), pin, head).unwrap();
        reopened.require_cold_head(head).unwrap();
        fs::write(path.join("INCIDENT_GUARD"), [1u8; 32]).unwrap();
        assert!(reopened.require_cold_head(head).is_err());
        drop(reopened);
        assert!(Store::open_pinned_inspection(&path, &public(1), pin, head).is_err());
        assert_eq!(fs::read(path.join("INCIDENT_GUARD")).unwrap(), [1; 32]);
        // An unsafe incident entry is never reconciled or ignored by cold open.
        fs::write(path.join("INCIDENT_GUARD"), [0u8; 32]).unwrap();
        fs::write(
            path.join("incidents/retained-invalid"),
            b"bad retained incident",
        )
        .unwrap();
        assert!(Store::open_pinned_inspection(&path, &public(1), pin, head).is_err());
        assert_eq!(
            fs::read(path.join("incidents/retained-invalid")).unwrap(),
            b"bad retained incident"
        );
    }
}

#[test]
fn cold_plan_refuses_fully_authenticated_unindexed_incident_and_changed_paged_manifest() {
    for rules in [bft::RULES, crate::paged_bft::RULES] {
        let mut h = Harness::with_rules(rules);
        h.retain = true;
        let x = forged_certificate(&h, h.node.bft_candidate(vec![], public(10)).unwrap());
        let y = forged_certificate(&h, h.node.bft_candidate(vec![], public(14)).unwrap());
        let proof = crate::conflict::Incident::from(
            crate::conflict::Conflict::from_snapshots(&x, &y).unwrap(),
        );
        proof.verify(&h.node.trust).unwrap();
        let raw = serde_json::to_vec(&proof).unwrap();
        let path = h
            .root
            .join("node/incidents")
            .join(format!("{}.json", proof.id().unwrap().to_hex()));
        fs::write(&path, &raw).unwrap();
        let head = h.node.storage_head().unwrap();
        assert!(h
            .node
            .require_cold_head(head)
            .unwrap_err()
            .contains("unindexed"));
        assert_eq!(fs::read(&path).unwrap(), raw);
        if rules == crate::paged_bft::RULES {
            let mut other = Harness::with_rules(rules);
            other.retain = true;
            let head = other.node.storage_head().unwrap();
            let manifest = other.root.join("node/ledger-events/stream.json");
            let before = fs::read(&manifest).unwrap();
            fs::write(&manifest, b"changed retained manifest").unwrap();
            assert!(other
                .node
                .require_cold_head(head)
                .unwrap_err()
                .contains("manifest changed"));
            assert_eq!(fs::read(manifest).unwrap(), b"changed retained manifest");
            assert!(!before.is_empty());
        }
    }
}
