use super::*;
use crate::storage::Store;
use ed25519_dalek::SigningKey;
use std::{fs, path::PathBuf};
fn public(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn sig(seed: u8, bytes: &[u8]) -> String {
    rld_core::sign_bytes(&hex::encode([seed; 32]), bytes).unwrap()
}
fn seeds() -> Vec<u8> {
    let mut keys = vec![2, 3, 4, 5];
    keys.sort_by_key(|&s| public(s));
    keys
}
fn accept_mined(n: &mut Store, commands: Vec<Command>) -> Result<()> {
    let mut block = n.template(commands, public(10))?;
    crate::mine(&mut block)?;
    n.accept(block)
}
struct Fixture {
    path: PathBuf,
    pin: Hash,
    store: Option<Store>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_rules(DOMAIN)
    }
    fn with_rules(rules: &str) -> Self {
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "rld-native-history-{}",
                rld_core::generate_identity().public_key
            ));
        let mut currency = Currency {
            format: DOMAIN.into(),
            fixture_only: true,
            implementation: implementation().unwrap(),
            origin: "earth".into(),
            authority: public(1),
            cap: Amount(300),
            block_reward: Amount(100),
            maturity: 2,
            signature: String::new(),
        };
        currency.signature = sig(1, &currency.bytes().unwrap());
        let pin = currency.id().unwrap();
        let mut admission = Admission {
            currency: pin,
            region: "earth".into(),
            rules: rules.into(),
            validators: seeds().into_iter().map(public).collect(),
            signature: String::new(),
        };
        admission.signature = sig(1, &admission.bytes().unwrap());
        let region = admission.id().unwrap();
        let store = Store::create(
            &path,
            Bootstrap {
                currency,
                admissions: vec![admission],
            },
            region,
            &public(1),
            pin,
        )
        .unwrap();
        Self {
            path,
            pin,
            store: Some(store),
        }
    }
    fn node(&mut self) -> &mut Store {
        self.store.as_mut().unwrap()
    }
    fn mine(&mut self) {
        accept_mined(self.node(), vec![]).unwrap();
    }
    fn finalize(&mut self) {
        let n = self.node();
        let statement = n.chain.statement(&n.trust).unwrap();
        let approvals = seeds()
            .into_iter()
            .map(|s| Approval {
                key: public(s),
                signature: sig(s, &statement.bytes().unwrap()),
            })
            .collect();
        n.finalize(Snapshot {
            base: n.chain.snapshot_base(),
            statement,
            approvals,
            blocks: n.chain.blocks.clone(),
            bft: None,
            epochs: vec![],
        })
        .unwrap();
    }
    fn close(&mut self) {
        self.store.take();
    }
    fn reopen(&mut self) {
        self.store = Some(Store::open(&self.path, &public(1), self.pin).unwrap());
    }
    fn manifest(&self) -> Manifest {
        manifest(&self.path).unwrap()
    }
    fn page(&self, r: &Reference) -> PathBuf {
        self.path
            .join("history")
            .join(format!("{}.json", r.hash.to_hex()))
    }
    fn put_manifest(&self, m: &Manifest) {
        fs::write(self.path.join("journal.json"), canonical(m).unwrap()).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.close();
        if std::thread::panicking() {
            return;
        }
        fs::remove_dir_all(&self.path).unwrap();
    }
}
#[test]
fn default_native_pages_replay_real_owner_payment_and_complete_finality() {
    let mut f = Fixture::new();
    for _ in 0..20 {
        f.mine();
    }
    f.finalize();
    let pin = f.pin;
    let n = f.node();
    let input = *n.chain.ledger.coins.keys().next().unwrap();
    let amount = n.chain.ledger.coins[&input].payment.amount;
    let intent = Intent {
        currency: pin,
        region: n.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(11),
            amount,
        }],
        fee: Amount::ZERO,
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 100,
    };
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(10),
            signature: sig(10, &intent.bytes().unwrap()),
        }],
        intent,
    };
    accept_mined(f.node(), vec![Command::Spend(Box::new(signed))]).unwrap();
    f.finalize();
    let expected = f.node().chain.ledger.root().unwrap();
    let tip = f.node().chain.tip().unwrap();
    let old = canonical(&f.node().journal).unwrap();
    let m = f.manifest();
    assert_eq!(m.pages.len(), 2);
    assert_eq!(m.snapshots.len(), 2);
    assert_eq!(m.journal_bytes, old.len());
    assert_eq!(canonical(&read_journal(&f.path).unwrap()).unwrap(), old);
    f.close();
    f.reopen();
    assert_eq!(f.node().chain.tip().unwrap(), tip);
    assert_eq!(f.node().chain.ledger.root().unwrap(), expected);
    assert!(f
        .node()
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)));
    assert_eq!(f.node().chain.ledger.minted, Amount(300));
}
#[test]
fn complete_old_pages_are_immutable_and_old_tail_residue_is_retained() {
    let mut f = Fixture::new();
    for _ in 0..17 {
        f.mine();
    }
    let m = f.manifest();
    let first = f.page(&m.pages[0]);
    let tail = f.page(&m.pages[1]);
    let raw = fs::read(&first).unwrap();
    let stamp = fs::metadata(&first).unwrap().modified().unwrap();
    f.mine();
    let new = f.manifest();
    assert_eq!(m.pages[0].hash, new.pages[0].hash);
    assert_ne!(m.pages[1].hash, new.pages[1].hash);
    assert_eq!(fs::read(&first).unwrap(), raw);
    assert_eq!(fs::metadata(&first).unwrap().modified().unwrap(), stamp);
    assert!(tail.exists());
}
#[test]
fn missing_altered_wrong_size_and_symlink_pages_refuse_without_rewrite() {
    let mut f = Fixture::new();
    f.mine();
    f.close();
    let m = f.manifest();
    let path = f.page(&m.pages[0]);
    let raw = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    fs::write(&path, &raw).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(&path, b"{}").unwrap();
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"{}");
    fs::write(&path, &raw).unwrap();
    let mut changed = m.clone();
    changed.pages[0].bytes += 1;
    f.put_manifest(&changed);
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    f.put_manifest(&m);
    #[cfg(unix)]
    {
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(f.path.join("journal.json"), &path).unwrap();
        assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    }
}
#[test]
fn reordered_pages_wrong_domain_and_noncanonical_manifest_refuse() {
    let mut f = Fixture::new();
    for _ in 0..18 {
        f.mine();
    }
    f.close();
    let m = f.manifest();
    let original = fs::read(f.path.join("journal.json")).unwrap();
    let mut altered = m.clone();
    altered.pages.reverse();
    f.put_manifest(&altered);
    assert!(read_journal(&f.path).is_err());
    altered = m.clone();
    altered.format = "other".into();
    f.put_manifest(&altered);
    assert!(read_journal(&f.path).is_err());
    let mut pretty = original.clone();
    pretty.push(b'\n');
    fs::write(f.path.join("journal.json"), &pretty).unwrap();
    assert!(read_journal(&f.path).is_err());
    fs::write(f.path.join("journal.json"), original).unwrap();
    f.reopen();
    assert_eq!(f.node().chain.height(), 18);
}
#[test]
fn self_consistent_forged_certificate_is_not_authorized_by_storage_hashes() {
    let mut f = Fixture::new();
    for _ in 0..4 {
        f.mine();
    }
    f.finalize();
    let mut forged = f.node().journal.clone();
    forged.evidence.snapshots[0].approvals[0].signature = "00".into();
    f.close();
    let bytes = prepare(&f.path, &forged).unwrap();
    fs::write(f.path.join("journal.json"), &bytes).unwrap();
    assert_eq!(
        canonical(&read_journal(&f.path).unwrap()).unwrap(),
        canonical(&forged).unwrap()
    );
    let before = fs::read(f.path.join("journal.json")).unwrap();
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), before);
}
#[test]
fn failed_manifest_publication_keeps_old_native_tip_and_unaccepted_page() {
    let mut f = Fixture::new();
    f.mine();
    let before = fs::read(f.path.join("journal.json")).unwrap();
    let used = archive_usage(&f.path.join("history")).unwrap().0;
    fs::write(f.path.join("journal.next"), b"retained interruption").unwrap();
    assert!(accept_mined(f.node(), vec![]).is_err());
    assert_eq!(f.node().chain.height(), 1);
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), before);
    assert!(archive_usage(&f.path.join("history")).unwrap().0 > used);
    assert_eq!(
        fs::read(f.path.join("journal.next")).unwrap(),
        b"retained interruption"
    );
    f.close();
    f.reopen();
    assert_eq!(f.node().chain.height(), 1);
    assert!(accept_mined(f.node(), vec![]).is_err());
    assert_eq!(f.node().chain.height(), 1);
}
#[test]
fn archive_capacity_accounts_orphans_and_refuses_before_manifest_mutation() {
    let mut f = Fixture::new();
    let m = f.manifest();
    let head = m.head().unwrap();
    for i in 0..MAX_FILES {
        let path = f.path.join("history").join(format!("{i:064x}.json"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).unwrap();
    }
    assert!(accept_mined(f.node(), vec![]).is_err());
    assert_eq!(f.manifest().head().unwrap(), head);
    assert_eq!(f.node().chain.height(), 0);
}
#[test]
fn legacy_inline_journal_refuses_unchanged() {
    let mut f = Fixture::new();
    let inline = canonical(&f.node().journal).unwrap();
    f.close();
    fs::write(f.path.join("journal.json"), &inline).unwrap();
    assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), inline);
}
#[test]
fn external_latest_head_refuses_a_valid_old_manifest_before_mutation() {
    let mut f = Fixture::new();
    let old = fs::read(f.path.join("journal.json")).unwrap();
    let oldhead = f.manifest().head().unwrap();
    f.mine();
    let latest = fs::read(f.path.join("journal.json")).unwrap();
    let latesthead = f.manifest().head().unwrap();
    f.close();
    fs::write(f.path.join("journal.json"), &old).unwrap();
    assert!(Store::open_pinned(&f.path, &public(1), f.pin, latesthead).is_err());
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), old);
    // Without the independent retained observation, genesis is valid old history.
    let unpinned = Store::open(&f.path, &public(1), f.pin).unwrap();
    assert_eq!(unpinned.chain.height(), 0);
    drop(unpinned);
    fs::write(f.path.join("journal.json"), &latest).unwrap();
    assert!(Store::open_pinned(&f.path, &public(1), f.pin, oldhead).is_err());
    let pinned = Store::open_pinned(&f.path, &public(1), f.pin, latesthead).unwrap();
    assert_eq!(pinned.chain.height(), 1);
    drop(pinned);
}
#[test]
fn pinned_open_refuses_pending_incident_without_reconciling_it() {
    let mut f = Fixture::new();
    let head = f.manifest().head().unwrap();
    f.close();
    fs::write(f.path.join("INCIDENT_GUARD"), [1u8; 32]).unwrap();
    let before = fs::read(f.path.join("journal.json")).unwrap();
    assert!(Store::open_pinned(&f.path, &public(1), f.pin, head)
        .err()
        .unwrap()
        .contains("pending incident"));
    assert_eq!(fs::read(f.path.join("journal.json")).unwrap(), before);
    assert_eq!(fs::read(f.path.join("INCIDENT_GUARD")).unwrap(), [1u8; 32]);
}
#[test]
fn rehashed_page_with_wrong_height_or_store_scope_still_refuses() {
    let mut f = Fixture::new();
    f.mine();
    f.close();
    let mut m = f.manifest();
    let original = m.clone();
    let raw = fs::read(f.page(&m.pages[0])).unwrap();
    let base: Object = decode(&raw).unwrap();
    for wrong_scope in [false, true] {
        let mut changed = base.clone();
        if wrong_scope {
            changed.region = Hash([3; 32]);
        } else {
            match &mut changed.payload {
                Payload::Events(p) => p.height_after += 1,
                _ => panic!("event page"),
            }
        }
        let (r, bytes) = reference(&changed).unwrap();
        let path = f.page(&r);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).unwrap();
        file.write_all(&bytes).unwrap();
        drop(file);
        m = original.clone();
        m.pages[0] = r;
        f.put_manifest(&m);
        assert!(Store::open(&f.path, &public(1), f.pin).is_err());
    }
    f.put_manifest(&original);
    f.reopen();
    assert_eq!(f.node().chain.height(), 1);
}
#[test]
fn native_block_limit_remains_a_real_refusal_in_paged_storage() {
    let mut f = Fixture::new();
    for _ in 0..MAX_BLOCKS {
        f.mine();
    }
    let head = f.manifest().head().unwrap();
    assert!(accept_mined(f.node(), vec![]).is_err());
    assert_eq!(f.manifest().head().unwrap(), head);
    f.close();
    f.reopen();
    assert_eq!(f.node().chain.height(), MAX_BLOCKS as u64);
    assert_eq!(f.node().chain.ledger.minted, Amount(300));
}
#[path = "history_prefix_tests.rs"]
mod prefixes;

#[path = "history_paged_tests.rs"]
mod paged;
