//! These tests exercise native persistence and adversarial failures, not just
//! the serialization of the new fields. All keys are public test fixtures.
use super::*;
use crate::{epoch::Transition, signer::Agent};
use std::fs;
struct Key {
    seed: u8,
    dir: PathBuf,
    file: PathBuf,
    head: Hash,
}
impl Key {
    fn create(root: &std::path::Path, store: &Store, seed: u8) -> Self {
        let dir = root.join(format!("signer-{seed}"));
        let file = root.join(format!("key-{seed}.json"));
        fs::write(
            &file,
            serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([seed;32])})).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let agent = Agent::create(&dir, store, public(seed)).unwrap();
        let head = agent.journal.head().unwrap();
        drop(agent);
        Self {
            seed,
            dir,
            file,
            head,
        }
    }
    fn checkpoint(&mut self, store: &Store) -> Approval {
        let mut agent = Agent::open(&self.dir, store).unwrap();
        let receipt = agent.checkpoint(store, &self.file, self.head).unwrap();
        assert_eq!(receipt.previous_head, self.head);
        self.head = receipt.lock_head;
        receipt.approval
    }
    fn handoff(&mut self, store: &Store, proposal: &Transition) -> Approval {
        let mut agent = Agent::open(&self.dir, store).unwrap();
        let receipt = agent
            .handoff(store, proposal.clone(), &self.file, self.head)
            .unwrap();
        self.head = receipt.lock_head;
        receipt.approval
    }
}
fn setup() -> (PathBuf, Store, Vec<Key>) {
    let f = Fixture::new();
    let (root, store) = stored_fixture(&f, &f.earth);
    let agents = keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect();
    (root, store, agents)
}
fn certify(store: &mut Store, agents: &mut [Key]) -> Snapshot {
    let mut snapshot = store.snapshot_request().unwrap();
    snapshot.approvals = agents.iter_mut().map(|k| k.checkpoint(store)).collect();
    store.finalize(snapshot.clone()).unwrap();
    snapshot
}
fn step(store: &mut Store, miner: u8) {
    let mut block = store.template(vec![], public(miner)).unwrap();
    mine(&mut block).unwrap();
    store.accept(block).unwrap();
}
fn new_keys() -> Vec<u8> {
    let mut k = vec![62, 63, 64, 65];
    k.sort_by_key(|s| public(*s));
    k
}
fn handoff(store: &Store, old: &mut [Key], new: &mut [Key]) -> Transition {
    let mut proof = store
        .epoch_request(new.iter().map(|k| public(k.seed)).collect())
        .unwrap();
    let unsigned = proof.clone();
    proof.old_approvals = old
        .iter_mut()
        .map(|k| k.handoff(store, &unsigned))
        .collect();
    proof.new_approvals = new
        .iter_mut()
        .map(|k| k.handoff(store, &unsigned))
        .collect();
    proof
}
#[test]
fn signer_persists_before_response_and_recovers_exact_retry_after_restart() {
    let (root, store, mut agents) = setup();
    let key = &mut agents[0];
    let old = key.head;
    let approval = key.checkpoint(&store);
    let new = key.head;
    let mut restarted = Agent::open(&key.dir, &store).unwrap();
    assert_eq!(restarted.journal.head().unwrap(), new);
    for expected in [old, new] {
        let retry = restarted.checkpoint(&store, &key.file, expected).unwrap();
        assert_eq!(retry.approval, approval);
        assert_eq!(retry.lock_head, new);
    }
    assert_eq!(restarted.journal.records.len(), 1);
    drop(restarted);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn stale_signer_backup_is_rejected_by_the_separately_retained_latest_head() {
    let (root, mut store, mut agents) = setup();
    let backup = fs::read(agents[0].dir.join("signer.json")).unwrap();
    certify(&mut store, &mut agents);
    step(&mut store, 10);
    let retained = agents[0].head;
    fs::write(agents[0].dir.join("signer.json"), backup).unwrap();
    let mut restored = Agent::open(&agents[0].dir, &store).unwrap();
    let error = restored
        .checkpoint(&store, &agents[0].file, retained)
        .unwrap_err();
    assert!(error.contains("caller-retained"));
    assert!(restored.journal.records.is_empty());
    // Restoring both the journal and every external pin is expressly outside
    // this guarantee. No self-generated status head is treated as external.
    drop(restored);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn signer_refuses_forks_and_wrong_keys_and_uses_an_exclusive_lock() {
    let (root, store, mut agents) = setup();
    agents[0].checkpoint(&store);
    let mut agent = Agent::open(&agents[0].dir, &store).unwrap();
    assert!(Agent::open(&agents[0].dir, &store).is_err());
    let b = bootstrap();
    let pin = b.currency.id().unwrap();
    let mut fork =
        Store::create(&root.join("fork"), b, store.chain.region, &public(1), pin).unwrap();
    for _ in 0..5 {
        step(&mut fork, 13);
    }
    assert!(agent
        .checkpoint(&fork, &agents[0].file, agents[0].head)
        .unwrap_err()
        .contains("prefix"));
    assert_eq!(agent.journal.records.len(), 1);
    drop(agent);
    let mut unused = Agent::open(&agents[1].dir, &store).unwrap();
    assert!(unused
        .checkpoint(&store, &agents[0].file, agents[1].head)
        .unwrap_err()
        .contains("pinned signer"));
    drop(unused);
    drop(fork);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn signer_corruption_and_write_failure_never_release_a_signature() {
    let (root, store, agents) = setup();
    let mut agent = Agent::open(&agents[0].dir, &store).unwrap();
    fs::write(agents[0].dir.join("signer.next"), b"interrupted write").unwrap();
    assert!(agent
        .checkpoint(&store, &agents[0].file, agents[0].head)
        .is_err());
    fs::remove_file(agents[0].dir.join("signer.next")).unwrap();
    assert!(agent
        .checkpoint(&store, &agents[0].file, agents[0].head)
        .unwrap_err()
        .contains("reopen"));
    assert!(agent.journal.records.is_empty());
    drop(agent);
    let mut reopened = Agent::open(&agents[0].dir, &store).unwrap();
    let receipt = reopened
        .checkpoint(&store, &agents[0].file, agents[0].head)
        .unwrap();
    drop(reopened);
    let mut journal: signer::Journal =
        storage::read_json(&agents[0].dir.join("signer.json")).unwrap();
    journal.records[0].approval.signature = "00".into();
    fs::write(
        agents[0].dir.join("signer.json"),
        serde_json::to_vec(&journal).unwrap(),
    )
    .unwrap();
    assert!(Agent::open(&agents[0].dir, &store).is_err());
    assert_ne!(receipt.lock_head, agents[0].head);
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn joint_epoch_handoff_survives_restart_and_preserves_currency_and_balances() {
    let (root, mut store, mut old) = setup();
    let closing = certify(&mut store, &mut old);
    assert!(Agent::create(&root.join("late"), &store, public(old[0].seed)).is_err());
    let mut new = new_keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect::<Vec<_>>();
    let proof = handoff(&store, &mut old, &mut new);
    let pin = store.trust.currency().unwrap();
    let before = store.chain.ledger.root().unwrap();
    let epoch = store.install_epoch(proof.clone()).unwrap();
    assert_eq!(before, store.chain.ledger.root().unwrap());
    assert_eq!(pin, store.trust.currency().unwrap());
    drop(store);
    let mut store = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(store.chain.epoch, epoch);
    step(&mut store, 10);
    let snapshot = certify(&mut store, &mut new);
    assert_eq!(
        snapshot.statement.previous,
        Some(closing.statement.id().unwrap())
    );
    assert_eq!(snapshot.epochs, vec![proof]);
    assert_eq!(store.chain.ledger.minted, Amount(300));
    let mut remote = VerifiedEvidence::default();
    remote.add(closing, &store.trust).unwrap();
    remote.add(snapshot.clone(), &store.trust).unwrap();
    step(&mut store, 10);
    let followup = certify(&mut store, &mut new);
    let mut missing = followup.clone();
    missing.epochs.clear();
    assert!(remote
        .add(missing, &store.trust)
        .unwrap_err()
        .contains("omits"));
    remote.add(followup, &store.trust).unwrap();
    assert!(old.iter_mut().all(|k| Agent::open(&k.dir, &store)
        .unwrap()
        .checkpoint(&store, &k.file, k.head)
        .is_err()));
    drop(store);
    let reopened = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(reopened.chain.epoch, epoch);
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn epoch_missing_consent_wrong_fence_or_number_is_atomic_and_sealed_signer_stays_sealed() {
    let (root, mut store, mut old) = setup();
    certify(&mut store, &mut old);
    let mut new = new_keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect::<Vec<_>>();
    let unsigned = store
        .epoch_request(new_keys().into_iter().map(public).collect())
        .unwrap();
    let old_vote = old[0].handoff(&store, &unsigned);
    let mut different = unsigned.clone();
    different.statement.validators.reverse();
    assert!(Agent::open(&old[0].dir, &store)
        .unwrap()
        .handoff(&store, different, &old[0].file, old[0].head)
        .is_err());
    step(&mut store, 10);
    assert!(Agent::open(&old[0].dir, &store)
        .unwrap()
        .checkpoint(&store, &old[0].file, old[0].head)
        .unwrap_err()
        .contains("sealed"));
    // Independent verifier also requires all old and all new votes.
    let mut proof = unsigned.clone();
    proof.old_approvals = keys()
        .into_iter()
        .map(|s| Approval {
            key: public(s),
            signature: signature(s, &unsigned.statement.bytes().unwrap()),
        })
        .collect();
    proof.old_approvals[0] = old_vote;
    proof.new_approvals = new
        .iter_mut()
        .map(|k| k.handoff(&store, &unsigned))
        .collect();
    let mut verifier = store.evidence.clone();
    let mut missing = proof.clone();
    missing.new_approvals.pop();
    assert!(verifier.install_epoch(missing, &store.trust).is_err());
    let mut wrong = proof.clone();
    wrong.statement.number = 2;
    assert!(verifier.install_epoch(wrong, &store.trust).is_err());
    let mut wrong = proof.clone();
    wrong.statement.closing_height += 1;
    assert!(verifier.install_epoch(wrong, &store.trust).is_err());
    let before = store.chain.ledger.root().unwrap();
    assert!(store.install_epoch(proof).is_err());
    assert_eq!(before, store.chain.ledger.root().unwrap());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn incompatible_joint_handoffs_are_authenticated_and_quarantined() {
    let (root, mut store, mut old) = setup();
    certify(&mut store, &mut old);
    let mut new = new_keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect::<Vec<_>>();
    let proof = handoff(&store, &mut old, &mut new);
    let mut competing = proof.clone();
    let mut other = vec![72, 73, 74, 75];
    other.sort_by_key(|s| public(*s));
    competing.statement.validators = other.iter().copied().map(public).collect();
    // Deliberate fixture private-key bypass, not produced by locked agents.
    let bytes = competing.statement.bytes().unwrap();
    competing.old_approvals = keys()
        .into_iter()
        .map(|s| Approval {
            key: public(s),
            signature: signature(s, &bytes),
        })
        .collect();
    competing.new_approvals = other
        .into_iter()
        .map(|s| Approval {
            key: public(s),
            signature: signature(s, &bytes),
        })
        .collect();
    conflict::Conflict::from_handoffs(&proof, &competing, &[])
        .unwrap()
        .verify(&store.trust)
        .unwrap();
    store.install_epoch(proof).unwrap();
    let before = store.chain.ledger.root().unwrap();
    assert!(store
        .install_epoch(competing)
        .unwrap_err()
        .contains("retained"));
    assert_eq!(store.conflicts.len(), 1);
    assert_eq!(before, store.chain.ledger.root().unwrap());
    assert!(store.template(vec![], public(10)).is_err());
    let pin = store.trust.currency().unwrap();
    drop(store);
    let restored = Store::open(&root, &public(1), pin).unwrap();
    assert_eq!(restored.conflicts.len(), 1);
    assert!(restored.snapshot_request().is_err());
    drop(restored);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn old_era_certificate_beyond_joint_closing_is_retained_even_on_same_prefix() {
    let (root, mut store, mut old) = setup();
    certify(&mut store, &mut old);
    let mut new = new_keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect::<Vec<_>>();
    let proof = handoff(&store, &mut old, &mut new);
    step(&mut store, 10);
    // Deliberate old-key bypass of the locked signers, after their seal.
    let old_certificate = checkpoint(&store.chain, &store.trust);
    store.finalize(old_certificate).unwrap();
    let before = store.chain.ledger.root().unwrap();
    assert!(store
        .install_epoch(proof)
        .unwrap_err()
        .contains("retired-era"));
    assert_eq!(store.conflicts.len(), 1);
    assert_eq!(before, store.chain.ledger.root().unwrap());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn a_second_epoch_with_overlapping_validators_has_one_monotonic_offline_authority_chain() {
    let (root, mut store, mut old) = setup();
    certify(&mut store, &mut old);
    let mut first = new_keys()
        .into_iter()
        .map(|s| Key::create(&root, &store, s))
        .collect::<Vec<_>>();
    let proof1 = handoff(&store, &mut old, &mut first);
    store.install_epoch(proof1).unwrap();
    step(&mut store, 10);
    certify(&mut store, &mut first);
    let mut next = vec![62, 63, 82, 83];
    next.sort_by_key(|s| public(*s));
    let mut second = next
        .into_iter()
        .map(|seed| {
            if let Some(index) = first.iter().position(|k| k.seed == seed) {
                let k = &first[index];
                Key {
                    seed,
                    dir: k.dir.clone(),
                    file: k.file.clone(),
                    head: k.head,
                }
            } else {
                Key::create(&root, &store, seed)
            }
        })
        .collect::<Vec<_>>();
    let mut proof2 = store
        .epoch_request(second.iter().map(|k| public(k.seed)).collect())
        .unwrap();
    let unsigned = proof2.clone();
    proof2.old_approvals = first
        .iter_mut()
        .map(|k| k.handoff(&store, &unsigned))
        .collect();
    for k in &mut second {
        if let Some(existing) = first.iter().find(|old| old.seed == k.seed) {
            k.head = existing.head;
        }
        proof2.new_approvals.push(k.handoff(&store, &unsigned));
    }
    assert_eq!(proof2.statement.number, 2);
    store.install_epoch(proof2).unwrap();
    step(&mut store, 10);
    let latest = certify(&mut store, &mut second);
    assert_eq!(latest.epochs.len(), 2);
    let archive = store.journal.evidence.clone();
    let independent = VerifiedEvidence::verify(&archive, &store.trust).unwrap();
    assert_eq!(independent.epoch_proofs(store.chain.region).len(), 2);
    assert_eq!(store.chain.ledger.minted, Amount(300));
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
