use super::*;

fn bundle() -> ProofBundle {
    ProofBundle::from_proof(
        Hash([1; 32]),
        Hash([2; 32]),
        Hash([3; 32]),
        Hash([4; 32]),
        42,
        b"candidate source lock proof bytes",
    )
    .unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rld-courier-{name}-{}-{unique}",
        std::process::id()
    ))
}

#[test]
fn delayed_file_delivery_and_retries_preserve_one_exact_bundle() {
    let source_dir = temp_dir("source");
    let destination_dir = temp_dir("destination");
    let message = bundle();
    let id = message.id().unwrap();
    let export_id = message.export_id;
    {
        let mut source = CourierStore::open(&source_dir).unwrap();
        assert!(source.enqueue(message.clone()).unwrap());
        assert!(!source.enqueue(message.clone()).unwrap());
        assert_eq!(source.len(), 1);
    }
    // The destination is opened only after the source has stopped: the file
    // can cross a long disconnected link without a shared live database.
    {
        let source = CourierStore::open(&source_dir).unwrap();
        let carried = source
            .bundle_for_export(message.source_chain_id, export_id)
            .unwrap()
            .unwrap();
        assert_eq!(carried.id().unwrap(), id);
        let mut destination = CourierStore::open(&destination_dir).unwrap();
        assert!(destination.enqueue(carried.clone()).unwrap());
        assert!(!destination.enqueue(carried).unwrap());
    }
    let destination = CourierStore::open(&destination_dir).unwrap();
    assert_eq!(
        destination
            .bundle_for_export(message.source_chain_id, export_id)
            .unwrap(),
        Some(message)
    );
    drop(destination);
    fs::remove_dir_all(source_dir).unwrap();
    fs::remove_dir_all(destination_dir).unwrap();
}

#[test]
fn malformed_or_unbound_proof_fails_before_storage() {
    let mut invalid = bundle();
    invalid.destination_chain_id = invalid.source_chain_id;
    assert!(invalid.validate().is_err());
    invalid = bundle();
    invalid.proof_hex = invalid.proof_hex.to_uppercase();
    assert!(invalid.validate().is_err());
    invalid = bundle();
    invalid.proof_sha256 = Hash([9; 32]);
    assert!(invalid.validate().is_err());
    invalid = bundle();
    invalid.source_height = 0;
    assert!(invalid.validate().is_err());
    assert!(ProofBundle::from_proof(
        Hash([1; 32]),
        Hash([2; 32]),
        Hash([3; 32]),
        Hash([4; 32]),
        1,
        &vec![7; MAX_PROOF_BYTES + 1],
    )
    .is_err());
    let mut json = serde_json::to_value(bundle()).unwrap();
    json["source_height"] = serde_json::json!(42);
    assert!(serde_json::from_value::<ProofBundle>(json.clone()).is_err());
    json["source_height"] = serde_json::json!("042");
    assert!(serde_json::from_value::<ProofBundle>(json).is_err());
}

#[test]
fn duplicate_export_with_changed_checkpoint_is_rejected() {
    let dir = temp_dir("conflict");
    let original = bundle();
    let mut conflicting = original.clone();
    conflicting.source_checkpoint = Hash([8; 32]);
    let mut store = CourierStore::open(&dir).unwrap();
    store.enqueue(original.clone()).unwrap();
    assert!(store.enqueue(conflicting.clone()).is_err());
    assert_eq!(
        store
            .bundle_for_export(original.source_chain_id, original.export_id)
            .unwrap(),
        Some(original)
    );
    drop(store);
    let mut restored = CourierStore::open(&dir).unwrap();
    assert!(restored.enqueue(conflicting).is_err());
    drop(restored);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_revisions_are_retained_but_never_selected_implicitly() {
    let dir = temp_dir("revision");
    let original = bundle();
    let original_id = original.id().unwrap();
    let mut later = original.clone();
    later.source_checkpoint = Hash([8; 32]);
    later.source_height += 5;
    let later_id = later.id().unwrap();
    {
        let mut store = CourierStore::open(&dir).unwrap();
        assert!(store.enqueue(original.clone()).unwrap());
        assert!(store.enqueue_variant(later.clone()).unwrap());
        assert!(!store.enqueue_variant(later.clone()).unwrap());
        assert_eq!(store.len(), 2);
        assert!(store
            .bundle_for_export(original.source_chain_id, original.export_id)
            .is_err());
        assert_eq!(store.bundle_by_id(original_id).unwrap(), original);
        assert_eq!(store.bundle_by_id(later_id).unwrap(), later);
    }
    let restored = CourierStore::open(&dir).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(
        restored.bundle_ids_for_export(original.source_chain_id, original.export_id),
        vec![original_id, later_id]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    assert!(restored
        .bundle_for_export(original.source_chain_id, original.export_id)
        .is_err());
    assert_eq!(restored.bundle_by_id(later_id).unwrap(), later);
    drop(restored);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn identical_export_bytes_from_distinct_source_chains_do_not_collide() {
    let dir = temp_dir("distinct-source");
    let first = bundle();
    let mut second = first.clone();
    second.source_chain_id = Hash([9; 32]);
    let mut store = CourierStore::open(&dir).unwrap();
    assert!(store.enqueue(first.clone()).unwrap());
    assert!(store.enqueue(second.clone()).unwrap());
    assert_eq!(store.len(), 2);
    assert_eq!(
        store
            .bundle_for_export(first.source_chain_id, first.export_id)
            .unwrap(),
        Some(first)
    );
    assert_eq!(
        store
            .bundle_for_export(second.source_chain_id, second.export_id)
            .unwrap(),
        Some(second)
    );
    drop(store);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn single_owner_and_corruption_rejection_survive_restart() {
    let dir = temp_dir("corrupt");
    let message = bundle();
    let id = message.id().unwrap();
    let mut store = CourierStore::open(&dir).unwrap();
    assert!(CourierStore::open(&dir).is_err());
    store.enqueue(message).unwrap();
    drop(store);
    let path = dir.join(format!("{}.json", id.to_hex()));
    fs::write(path, b"{}").unwrap();
    assert!(CourierStore::open(&dir).is_err());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn incomplete_pending_delivery_has_no_authority() {
    let dir = temp_dir("pending");
    fs::create_dir_all(&dir).unwrap();
    let message = bundle();
    fs::write(
        dir.join(format!("{}.pending", message.id().unwrap().to_hex())),
        b"partial",
    )
    .unwrap();
    let mut store = CourierStore::open(&dir).unwrap();
    assert!(store.is_empty());
    assert!(store.enqueue(message).unwrap());
    drop(store);
    let restored = CourierStore::open(&dir).unwrap();
    assert_eq!(restored.len(), 1);
    drop(restored);
    fs::remove_dir_all(dir).unwrap();
}
