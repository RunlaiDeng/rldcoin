use super::*;
use crate::history_archive::{self as archive, Archive, Record};
use std::{collections::BTreeMap, fs, io::Write};
struct Image {
    source: PathBuf,
    root: PathBuf,
    archive: PathBuf,
    pin: Hash,
    head: Hash,
}
impl Image {
    fn new() -> Self {
        let f = Fixture::new();
        Self::from_fixture(&f, &f.earth)
    }
    fn from_fixture(f: &Fixture, chain: &Chain) -> Self {
        let (source, mut store) = stored_fixture(f, chain);
        store
            .finalize(checkpoint(&store.chain, &store.trust))
            .unwrap();
        let pin = store.trust.currency().unwrap();
        drop(store);
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-history-archive-{}",
                rld_core::generate_identity().public_key
            ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let head = crate::history::manifest(&source).unwrap().head().unwrap();
        Self {
            source,
            archive: root.join("archive"),
            root,
            pin,
            head,
        }
    }
    fn seal(&self) -> Archive {
        archive::seal(&self.source, &self.archive, &public(1), self.pin, self.head).unwrap()
    }
    fn target(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    fn restore(&self, name: &str) -> Store {
        let target = self.target(name);
        archive::restore(&self.archive, &target, &public(1), self.pin, self.head).unwrap();
        Store::open_pinned(&target, &public(1), self.pin, self.head).unwrap()
    }
    fn refresh(&mut self) {
        self.head = crate::history::manifest(&self.source)
            .unwrap()
            .head()
            .unwrap();
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        fs::remove_dir_all(&self.source).unwrap();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn bytes(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &std::path::Path, dir: &std::path::Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if fs::symlink_metadata(&p).unwrap().is_dir() {
                visit(root, &p, out)
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    fs::read(p).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn private_file(path: &std::path::Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut file = o.open(path).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn rewrite_index(image: &Image, head: Hash) -> Archive {
    let path = image.archive.join("archive.json");
    let mut index: Archive = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    index.native_head = head;
    let all = bytes(&image.archive.join("data"));
    index.files = all
        .into_iter()
        .map(|(name, raw)| {
            (
                name,
                Record {
                    bytes: raw.len() as u64,
                    sha256: Hash(Sha256::digest(&raw).into()),
                },
            )
        })
        .collect();
    index.retained_bytes = index.files.values().map(|f| f.bytes).sum();
    fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
    index
}
#[test]
fn full_native_pages_finality_real_payment_and_private_scopes_restore_exactly() {
    let mut image = Image::new();
    let mut node = Store::open_pinned(&image.source, &public(1), image.pin, image.head).unwrap();
    for _ in 0..20 {
        let mut block = node.template(vec![], public(10)).unwrap();
        mine(&mut block).unwrap();
        node.accept(block).unwrap();
    }
    let chosen = coins(&node.chain, 10)[0];
    let amount = node.chain.ledger.coins[&chosen].payment.amount;
    let payment = intent(
        &node.chain,
        &node.trust,
        vec![chosen],
        vec![Payment {
            owner: public(11),
            amount,
        }],
        None,
        None,
        0,
        0,
        &[10],
    );
    let mut block = node
        .template(vec![Command::Spend(Box::new(payment))], public(10))
        .unwrap();
    mine(&mut block).unwrap();
    node.accept(block).unwrap();
    node.finalize(checkpoint(&node.chain, &node.trust)).unwrap();
    let ledger = node.chain.ledger.clone();
    let finalized = node.chain.finalized;
    drop(node);
    image.refresh();
    private_file(
        &image.source.join("key.enc.json"),
        b"private-key-not-an-archive-input",
    );
    fs::create_dir(image.source.join("wallet-caller")).unwrap();
    private_file(
        &image.source.join("wallet-caller/head.json"),
        b"preserved-caller-head",
    );
    let before = bytes(&image.source);
    let index = image.seal();
    assert!(index
        .files
        .keys()
        .all(|p| !p.contains("key.enc") && !p.contains("wallet-caller")));
    assert_eq!(bytes(&image.source), before);
    let recovered = image.restore("restored");
    assert_eq!(
        recovered.chain.ledger.root().unwrap(),
        ledger.root().unwrap()
    );
    assert_eq!(recovered.chain.finalized, finalized);
    assert_eq!(recovered.chain.height(), 25);
    assert_eq!(
        crate::history::manifest(&image.target("restored"))
            .unwrap()
            .pages
            .len(),
        2
    );
    assert!(!image.target("restored/key.enc.json").exists());
    assert_eq!(bytes(&image.source), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(image.target("restored"))
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}
#[test]
fn immutable_tail_orphans_and_damaged_incident_residue_are_carried_without_value_rights() {
    let image = Image::new();
    let orphan = image
        .source
        .join("history")
        .join(format!("{}.json", Hash([0xab; 32]).to_hex()));
    private_file(&orphan, b"retained incomplete unaccepted object");
    let damaged = format!("damaged-incident-{}.bin", Hash([0xcd; 32]).to_hex());
    private_file(&image.source.join(&damaged), b"unaccepted forensic residue");
    let before = bytes(&image.source);
    let index = image.seal();
    assert!(index.files.contains_key(&damaged));
    let restored = image.restore("restored");
    assert_eq!(restored.chain.height(), 4);
    assert_eq!(
        fs::read(image.target("restored").join(&damaged)).unwrap(),
        b"unaccepted forensic residue"
    );
    assert_eq!(bytes(&image.source), before);
}
#[test]
fn latest_external_head_refuses_old_valid_archive_and_wrong_native_authority_before_target_creation(
) {
    let mut image = Image::new();
    let old = image.head;
    image.seal();
    let before = bytes(&image.archive);
    let mut source = Store::open_pinned(&image.source, &public(1), image.pin, old).unwrap();
    let mut block = source.template(vec![], public(10)).unwrap();
    mine(&mut block).unwrap();
    source.accept(block).unwrap();
    drop(source);
    image.refresh();
    let err = archive::restore(
        &image.archive,
        &image.target("latest"),
        &public(1),
        image.pin,
        image.head,
    )
    .unwrap_err();
    assert!(err.contains("externally retained"));
    assert!(!image.target("latest").exists());
    assert!(archive::restore(
        &image.archive,
        &image.target("wrong-authority"),
        &public(2),
        image.pin,
        old
    )
    .is_err());
    assert!(archive::restore(
        &image.archive,
        &image.target("wrong-currency"),
        &public(1),
        Hash([8; 32]),
        old
    )
    .is_err());
    assert_eq!(bytes(&image.archive), before);
    // Losing the actual external latest head permits a valid historical ledger;
    // no independently retained root or full rollback qualification is inferred.
    archive::restore(
        &image.archive,
        &image.target("historical-explicit"),
        &public(1),
        image.pin,
        old,
    )
    .unwrap();
    assert_eq!(
        Store::open_pinned(
            &image.target("historical-explicit"),
            &public(1),
            image.pin,
            old
        )
        .unwrap()
        .chain
        .height(),
        4
    );
}
#[test]
fn missing_corrupt_extra_and_traversal_entries_refuse_without_creating_target() {
    for mutation in 0..4 {
        let image = Image::new();
        image.seal();
        let data = image.archive.join("data");
        let original = fs::read(data.join("journal.json")).unwrap();
        match mutation {
            0 => fs::remove_file(data.join("journal.json")).unwrap(),
            1 => fs::write(data.join("journal.json"), b"corrupt").unwrap(),
            2 => private_file(&data.join("unlisted.json"), b"unlisted"),
            _ => {
                let path = image.archive.join("archive.json");
                let mut index: Archive = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                index.files.insert(
                    "../../escape".into(),
                    Record {
                        bytes: original.len() as u64,
                        sha256: Hash(Sha256::digest(&original).into()),
                    },
                );
                fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
            }
        }
        let before = bytes(&image.archive);
        assert!(archive::restore(
            &image.archive,
            &image.target("bad"),
            &public(1),
            image.pin,
            image.head
        )
        .is_err());
        assert!(!image.target("bad").exists());
        assert_eq!(bytes(&image.archive), before);
        assert!(!image.root.join("escape").exists());
    }
}
#[test]
fn fully_rehashed_forged_finality_still_requires_complete_native_authority() {
    let image = Image::new();
    image.seal();
    let data = image.archive.join("data");
    let mut journal = crate::history::read_journal(&data).unwrap();
    journal.evidence.snapshots[0].approvals[0].signature = "00".repeat(64);
    let manifest = crate::history::prepare(&data, &journal).unwrap();
    fs::write(data.join("journal.json"), manifest).unwrap();
    let head = crate::history::manifest(&data).unwrap().head().unwrap();
    rewrite_index(&image, head);
    let before = bytes(&image.archive);
    let refusal = archive::restore(
        &image.archive,
        &image.target("forged"),
        &public(1),
        image.pin,
        head,
    )
    .unwrap_err();
    assert!(!refusal.contains("inventory differs") && !refusal.contains("external retained"));
    assert!(
        refusal.contains("signature") || refusal.contains("hex"),
        "{refusal}"
    );
    assert!(!image.target("forged").exists());
    assert_eq!(bytes(&image.archive), before);
}
#[test]
fn interrupted_restore_keeps_marker_and_refuses_even_a_subsequently_complete_image() {
    let image = Image::new();
    let index = image.seal();
    let target = image.target("interrupted");
    let before = bytes(&image.archive);
    let refusal =
        archive::interrupt_restore(&image.archive, &target, &public(1), image.pin, image.head)
            .unwrap_err();
    assert!(refusal.contains("injected interruption"));
    assert!(target.join("RESTORING").is_file());
    assert!(Store::open(&target, &public(1), image.pin)
        .err()
        .unwrap()
        .contains("restoration is incomplete"));
    for name in index.files.keys() {
        if !target.join(name).exists() {
            private_file(
                &target.join(name),
                &fs::read(image.archive.join("data").join(name)).unwrap(),
            );
        }
    }
    assert!(
        Store::open_pinned(&target, &public(1), image.pin, image.head)
            .err()
            .unwrap()
            .contains("restoration is incomplete")
    );
    let retained = bytes(&target);
    assert!(archive::restore(&image.archive, &target, &public(1), image.pin, image.head).is_err());
    assert_eq!(bytes(&target), retained);
    assert_eq!(bytes(&image.archive), before);
    let f = Fixture::new();
    assert!(
        storage::recover_incident(&target, &public(1), image.pin, conflict_proof(&f))
            .unwrap_err()
            .contains("restoration is incomplete")
    );
}
#[test]
fn existing_target_and_caller_wallet_state_never_overwrite_or_merge() {
    let image = Image::new();
    image.seal();
    let target = image.target("existing");
    fs::create_dir(&target).unwrap();
    private_file(&target.join("head.json"), b"latest caller head");
    private_file(&target.join("pending.json"), b"pending owner approval");
    let retained = bytes(&target);
    assert!(archive::restore(&image.archive, &target, &public(1), image.pin, image.head).is_err());
    assert_eq!(bytes(&target), retained);
    assert!(archive::seal(
        &image.source,
        &image.archive,
        &public(1),
        image.pin,
        image.head
    )
    .is_err());
    assert!(archive::seal(
        &image.source,
        &image.source.join("backup"),
        &public(1),
        image.pin,
        image.head
    )
    .is_err());
}
#[test]
fn source_or_archive_lock_pending_guard_and_unpublished_archive_refuse() {
    let image = Image::new();
    let node = Store::open_pinned(&image.source, &public(1), image.pin, image.head).unwrap();
    assert!(archive::seal(
        &image.source,
        &image.archive,
        &public(1),
        image.pin,
        image.head
    )
    .is_err());
    assert!(!image.archive.exists());
    drop(node);
    image.seal();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(image.archive.join("LOCK"))
        .unwrap();
    lock.try_lock().unwrap();
    assert!(archive::restore(
        &image.archive,
        &image.target("locked"),
        &public(1),
        image.pin,
        image.head
    )
    .is_err());
    assert!(!image.target("locked").exists());
    drop(lock);
    private_file(&image.archive.join("ARCHIVING"), b"incomplete publication");
    assert!(archive::restore(
        &image.archive,
        &image.target("unpublished"),
        &public(1),
        image.pin,
        image.head
    )
    .unwrap_err()
    .contains("publication incomplete"));
    fs::write(image.source.join("INCIDENT_GUARD"), [3; 32]).unwrap();
    assert!(archive::seal(
        &image.source,
        &image.target("guard"),
        &public(1),
        image.pin,
        image.head
    )
    .unwrap_err()
    .contains("pending incident"));
    assert!(!image.target("guard").exists());
}
#[cfg(unix)]
#[test]
fn archive_link_permissions_and_source_manifest_residue_are_not_repaired() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for mutation in 0..3 {
        let image = Image::new();
        image.seal();
        let path = image.archive.join("data/journal.json");
        let original = fs::read(&path).unwrap();
        match mutation {
            0 => {
                let retained = image.root.join("retained.json");
                private_file(&retained, &original);
                fs::remove_file(&path).unwrap();
                symlink(&retained, &path).unwrap();
            }
            1 => fs::hard_link(&path, image.root.join("hardlink")).unwrap(),
            _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
        };
        assert!(archive::restore(
            &image.archive,
            &image.target("bad"),
            &public(1),
            image.pin,
            image.head
        )
        .is_err());
        assert!(!image.target("bad").exists());
    }
    let image = Image::new();
    private_file(
        &image.source.join("journal.next"),
        b"unaccepted native manifest",
    );
    let before = bytes(&image.source);
    assert!(archive::seal(
        &image.source,
        &image.archive,
        &public(1),
        image.pin,
        image.head
    )
    .unwrap_err()
    .contains("manifest residue"));
    assert_eq!(bytes(&image.source), before);
    assert!(!image.archive.exists());
}
#[test]
fn authenticated_incidents_quarantine_and_import_tombstones_survive_restoration() {
    let mut f = Fixture::new();
    let (_, eid) = f.imported();
    for _ in 0..2 {
        advance(&mut f.proxima, &f.trust, &f.evidence, vec![]);
    }
    finalize(&mut f.proxima, &f.trust, &mut f.evidence);
    let mut image = Image::from_fixture(&f, &f.proxima);
    let mut node = Store::open_pinned(&image.source, &public(1), image.pin, image.head).unwrap();
    node.observe_conflict(conflict_proof(&f)).unwrap();
    assert!(node.chain.ledger.imports.contains_key(&eid));
    drop(node);
    image.refresh();
    image.seal();
    let restored = image.restore("restored");
    assert!(restored.chain.ledger.imports.contains_key(&eid));
    assert!(restored.safety.regions.contains_key(&f.earth.region));
    assert_eq!(restored.conflicts.len(), 1);
    let payment = intent(
        &restored.chain,
        &restored.trust,
        coins(&restored.chain, 11),
        vec![Payment {
            owner: public(12),
            amount: Amount(78),
        }],
        None,
        None,
        0,
        0,
        &[11],
    );
    assert!(restored
        .template(vec![Command::Spend(Box::new(payment))], public(10))
        .is_err());
    drop(restored);
    let data = image.archive.join("data");
    let incident = fs::read_dir(data.join("incidents"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(incident).unwrap();
    rewrite_index(&image, image.head);
    assert!(archive::restore(
        &image.archive,
        &image.target("missing-incident"),
        &public(1),
        image.pin,
        image.head
    )
    .unwrap_err()
    .contains("indexed incident is missing"));
    assert!(!image.target("missing-incident").exists());
}
