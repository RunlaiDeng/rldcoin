//! Bounded private read-only attack copies; never copied signing keys/custody use.
use super::paged_recovery::copy_private;
use super::retained_native_replay::inventory;
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    scope: crate::retained_pages::Scope,
    pages: Vec<crate::history::Reference>,
    tail: Vec<bft::Record>,
    count: u64,
    head: Hash,
}
pub(super) fn reject_later_signature_and_missing_page(h: &Harness, minimum_records: u64) {
    let original = h.root.join(format!("signer-{}", h.seeds[0]));
    let bad = h.root.join("bad-over128-signer");
    copy_private(&original, &bad);
    let path = bad.join("bft-records/stream.json");
    let raw = crate::keystore::private_read(&path, MAX_BYTES).unwrap();
    let mut manifest: Manifest = serde_json::from_slice(&raw).unwrap();
    assert_eq!(serde_json::to_vec(&manifest).unwrap(), *raw);
    assert!(manifest.count > minimum_records);
    let last = manifest
        .tail
        .last_mut()
        .expect("new original timeout retained in bounded tail");
    let Message::Timeout(timeout) = &mut last.message else {
        panic!("original recovered timeout")
    };
    timeout.approval.signature = "00".repeat(64);
    manifest.head =
        crate::retained_pages::next_head(last.previous_head, manifest.count - 1, last).unwrap();
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let before = inventory(&h.root);
    let error = Agent::open(&bad, &h.node)
        .err()
        .expect("hash-consistent later signature must refuse");
    assert!(
        error.contains("signature"),
        "complete >128 native replay must reach bad signature: {error}"
    );
    assert_eq!(inventory(&h.root), before);
    let missing = h.root.join("missing-over128-page");
    copy_private(&original, &missing);
    let manifest: Manifest =
        crate::storage::read_json(&missing.join("bft-records/stream.json")).unwrap();
    let page = missing
        .join("bft-records/pages")
        .join(format!("{}.json", manifest.pages[0].hash.to_hex()));
    // Retain the removed copied bytes outside this attacker directory. No
    // original page, caller head or native authority is changed or pruned.
    fs::rename(page, h.root.join("missing-page-original-bytes")).unwrap();
    let before = inventory(&h.root);
    assert!(Agent::open(&missing, &h.node).is_err());
    assert_eq!(inventory(&h.root), before);
    println!("paged-capacity later_hash_consistent_bad_signature_refused=true missing_original_page_refused=true actual_records={} original_caller_heads_unchanged=true copied_keys=false",manifest.count);
}

#[test]
fn paged_capacity_missing_path_minimum_real_page_and_bad_signature() {
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    for n in 0..4 {
        super::paged_integration::retain(&h.root, n, h.heads[n]);
    }
    for _ in 0..2 {
        let s = super::paged_integration::certify(&mut h, vec![]);
        h.node.finalize(s).unwrap();
    }
    let context = Context::current(&h.node).unwrap();
    for round in 0..14 {
        super::paged_integration::sign(
            &mut h,
            0,
            Request::Timeout {
                context: context.clone(),
                round,
            },
        );
    }
    assert!(h.agents[0].record_count() > 16);
    h.agents.clear();
    reject_later_signature_and_missing_page(&h, 16);
}
