//! Public no-value signing fixtures. Separate identical-key journals compare
//! deterministic bytes only; they do not qualify copied-key/concurrent custody.
use super::*;
use crate::tests::public;
use crate::{bft, bft_network};

fn setup(label: &str) -> (Store, PathBuf, bft::Request, String, PathBuf) {
    let (h, source, root, _, records, export) =
        super::export_archive_tests::source_fixture_with_named_origin(
            66,
            16,
            crate::paged_bft::ORIGIN_NETWORK_RULES,
            label,
        );
    let destination = source.trust.named("proxima").unwrap();
    let mut node = Store::create(
        &root.join("destination"),
        h.bootstrap.clone(),
        destination,
        &public(1),
        source.trust.currency().unwrap(),
    )
    .unwrap();
    node.accept_complete_origin_history(CompleteOriginHistory {
        source: h.region,
        destination,
        export,
        snapshots: records
            .iter()
            .map(|r| match r {
                Record::Certified(s) => *s.clone(),
                _ => panic!("source certificate"),
            })
            .collect(),
    })
    .unwrap();
    let context = bft::Context::current(&node).unwrap();
    let key = context.keys(&node.trust, &node.evidence).unwrap()[0].clone();
    let seed = (2..=5).find(|n| public(*n) == key).unwrap();
    let key_file = root.join("public-fixture-key.json");
    crate::keystore::private_create(
        &key_file,
        &serde_json::to_vec(&serde_json::json!({
            "secret_key":format!("{seed:02x}").repeat(32)
        }))
        .unwrap(),
    )
    .unwrap();
    let request = bft::Request::Propose {
        round: 0,
        snapshot: Box::new(
            node.bft_candidate(node.complete_origin_pending_imports().unwrap(), public(20))
                .unwrap(),
        ),
        timeout: None,
    };
    (node, root, request, key, key_file)
}

#[test]
fn composed_signature_matches_standalone_complete_wire_and_holds_signer_lock() {
    let (node, root, request, key, key_file) = setup("earth-sign-equivalence");
    let mut standalone = bft::Agent::create(&root.join("standalone"), &node, key.clone()).unwrap();
    let initial = standalone.head().unwrap();
    let baseline = standalone
        .sign(&node, request.clone(), Some(&key_file), initial)
        .unwrap();
    let wire = bft_network::local_envelope(
        bft_network::Body::Signed(Box::new(baseline.message.clone())),
        &node,
    )
    .unwrap();
    let agent = bft::Agent::create(&root.join("composed"), &node, key.clone()).unwrap();
    assert_eq!(agent.head().unwrap(), initial);
    drop(agent);
    let native_head = node.storage_head().unwrap();
    let before = super::continuation_tests::inventory(&node.dir);
    let result = bft_network::sign_local_envelope(
        &serde_json::to_vec(&request).unwrap(),
        &node,
        &root.join("composed"),
        native_head,
        initial,
        &key,
        &key_file,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&result.signed).unwrap(),
        serde_json::to_vec(&baseline).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&result.envelope).unwrap(),
        serde_json::to_vec(&wire.envelope).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&result.checked).unwrap(),
        serde_json::to_vec(&wire.checked).unwrap()
    );
    assert!(bft::Agent::open(&root.join("composed"), &node).is_err());
    assert_eq!(before, super::continuation_tests::inventory(&node.dir));
    let head = result.signed.head;
    drop(result);
    let cold = bft::Agent::inspect_with_status(&root.join("composed"), &node).unwrap();
    assert_eq!(cold.0.head().unwrap(), head);
    assert_eq!(node.chain.height(), 0);
    assert!(node.chain.ledger.coins.is_empty());
}

#[test]
fn composed_stale_heads_key_invalid_request_and_capacity_never_sign() {
    let (node, root, request, key, key_file) = setup("earth-sign-negative");
    let dir = root.join("signer");
    let agent = bft::Agent::create(&dir, &node, key.clone()).unwrap();
    let head = agent.head().unwrap();
    drop(agent);
    let native = node.storage_head().unwrap();
    let original = super::continuation_tests::inventory(&root);
    let raw = serde_json::to_vec(&request).unwrap();
    for (ledger, signer, k) in [
        (Hash::ZERO, head, key.clone()),
        (native, Hash::ZERO, key.clone()),
        (native, head, public(9)),
    ] {
        assert!(
            bft_network::sign_local_envelope(&raw, &node, &dir, ledger, signer, &k, &key_file)
                .is_err()
        );
        assert_eq!(original, super::continuation_tests::inventory(&root));
    }
    let mut invalid = request.clone();
    if let bft::Request::Propose { round, .. } = &mut invalid {
        *round = 31;
    }
    assert!(bft_network::sign_local_envelope(
        &serde_json::to_vec(&invalid).unwrap(),
        &node,
        &dir,
        native,
        head,
        &key,
        &key_file
    )
    .is_err());
    assert!(bft_network::sign_local_envelope(
        &vec![0; crate::contact::MAX_PAYLOAD + 1],
        &node,
        &dir,
        native,
        head,
        &key,
        &key_file
    )
    .is_err());
    assert_eq!(original, super::continuation_tests::inventory(&root));
    assert!(bft::Agent::recover_response(&dir, &node, request, head).is_err());
    assert_eq!(original, super::continuation_tests::inventory(&root));
}

#[test]
fn post_sign_pack_failure_preserves_exact_recover_only_response_and_lock() {
    let (node, root, request, key, key_file) = setup("earth-sign-recover");
    let dir = root.join("signer");
    let agent = bft::Agent::create(&dir, &node, key.clone()).unwrap();
    let old = agent.head().unwrap();
    drop(agent);
    let native = node.storage_head().unwrap();
    assert!(bft_network::sign_local_pack_failure_for_test(
        &serde_json::to_vec(&request).unwrap(),
        &node,
        &dir,
        native,
        old,
        &key,
        &key_file
    )
    .is_err());
    let before = super::continuation_tests::inventory(&root);
    let result = bft::Agent::recover_response(&dir, &node, request.clone(), old).unwrap();
    assert!(result.recovered_exact_retry);
    assert_ne!(result.head, old);
    assert_eq!(result.previous_head, old);
    assert_eq!(before, super::continuation_tests::inventory(&root));
    let packed = bft_network::local_envelope(
        bft_network::Body::Signed(Box::new(result.message.clone())),
        &node,
    )
    .unwrap();
    assert!(packed.checked.value.is_some());
    assert!(bft_network::sign_local_envelope(
        &serde_json::to_vec(&request).unwrap(),
        &node,
        &dir,
        native,
        old,
        &key,
        &key_file
    )
    .is_err());
    assert_eq!(before, super::continuation_tests::inventory(&root));
    let cold = bft::Agent::inspect_with_status(&dir, &node).unwrap();
    assert_eq!(cold.0.head().unwrap(), result.head);
    assert_eq!(node.chain.height(), 0);
    assert!(node.chain.ledger.coins.is_empty());
}
