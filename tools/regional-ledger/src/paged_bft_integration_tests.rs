use super::retained_native_replay::inventory;
use super::*;
use std::process::Command as Process;
#[derive(Serialize, Deserialize)]
struct Pins {
    currency: Hash,
    native: Hash,
    seeds: Vec<u8>,
    signers: Vec<Hash>,
    wallet: Hash,
}
fn retain(root: &Path, n: usize, head: Hash) {
    let next = root.join(format!("caller-{n}.next"));
    crate::keystore::private_create(&next, &head.0).unwrap();
    fs::rename(next, root.join(format!("caller-{n}.head"))).unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
}
fn sign(h: &mut Harness, n: usize, request: Request) -> bft::Signed {
    let raw = crate::keystore::private_read(&h.root.join(format!("caller-{n}.head")), 32).unwrap();
    assert_eq!(*raw, h.heads[n].0);
    let signed = h.agents[n]
        .sign(
            &h.node,
            request,
            Some(&h.root.join(format!("key-{}.json", h.seeds[n]))),
            h.heads[n],
        )
        .unwrap();
    retain(&h.root, n, signed.head);
    h.heads[n] = signed.head;
    signed
}
fn certify(h: &mut Harness, commands: Vec<crate::Command>) -> Snapshot {
    let snapshot = h.node.bft_candidate(commands, public(10)).unwrap();
    let c = Context::current(&h.node).unwrap();
    let keys = h.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let leader = bft::leader(&c, 0, &keys).unwrap();
    let n = keys.iter().position(|k| k == &leader).unwrap();
    let Message::Proposal(p) = sign(
        h,
        n,
        Request::Propose {
            round: 0,
            snapshot: Box::new(snapshot),
            timeout: None,
        },
    )
    .message
    else {
        panic!()
    };
    let mut votes = vec![];
    for n in 0..4 {
        let Message::Vote(v) = sign(h, n, Request::Prepare(p.clone())).message else {
            panic!()
        };
        votes.push(*v);
    }
    let q = Quorum::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
    let mut votes = vec![];
    for n in 0..4 {
        let Message::Vote(v) = sign(
            h,
            n,
            Request::Commit {
                proposal: p.clone(),
                prepared: q.clone(),
            },
        )
        .message
        else {
            panic!()
        };
        votes.push(*v);
    }
    let committed = Quorum::combine(votes, &h.node.trust, &h.node.evidence).unwrap();
    let mut snapshot = *p.snapshot;
    snapshot.bft = Some(Certificate {
        prepared: q,
        committed,
    });
    snapshot
}
#[test]
#[ignore = "bounded parent calls a fresh pinned child process explicitly"]
fn paged_native_integration_cold_child() {
    let root = PathBuf::from(
        std::env::var_os("RLD_PAGED_INTEGRATION_COLD_ROOT").expect("bounded parent private path"),
    );
    let pins: Pins = crate::storage::read_json(&root.join("integration-pins.json")).unwrap();
    let before = inventory(&root);
    let node =
        Store::open_pinned(&root.join("node"), &public(1), pins.currency, pins.native).unwrap();
    assert_eq!(node.chain.height(), 65);
    assert_eq!(node.blocks().unwrap().count(), 65);
    for (n, seed) in pins.seeds.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), pins.signers[n]);
        assert!(agent.record_count() > 128);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            pins.signers[n].0
        );
    }
    let owner = crate::wallet_agent::Agent::open(&root.join("owner-wallet"), &node).unwrap();
    assert_eq!(owner.journal.head().unwrap(), pins.wallet);
    owner.view(&node, pins.wallet).unwrap();
    assert!(node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11)
            && c.payment.amount == Amount(99)
            && c.mature <= 65));
    assert_eq!(inventory(&root), before);
    println!("paged-native cold-child height65 full_genesis_native_and_four_signer_replay=true native_wallet99_mature=true unchanged_private_inventory=true independent_freshness=false");
}
#[test]
fn paged_store_and_four_native_signers_cross_record_and_active_boundaries_with_fresh_process_cold()
{
    let started = std::time::Instant::now();
    let mut h = Harness::with_rules(crate::paged_bft::RULES);
    h.retain = true;
    for n in 0..4 {
        retain(&h.root, n, h.heads[n]);
    }
    crate::keystore::private_create(
        &h.root.join("owner-key.json"),
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([10;32])})).unwrap(),
    )
    .unwrap();
    let mut owner = None;
    let mut owner_head = Hash::ZERO;
    let mut initial_certificate = None;
    for height in 1..=65 {
        let commands = if height == 4 {
            let mut wallet = crate::wallet_agent::Agent::create(
                &h.root.join("owner-wallet"),
                &h.node,
                public(10),
            )
            .unwrap();
            let old = wallet.journal.head().unwrap();
            let prepared = wallet
                .prepare(
                    &h.node,
                    crate::wallet::Request {
                        owner: public(10),
                        participants: vec![],
                        inputs: None,
                        outputs: vec![Payment {
                            owner: public(11),
                            amount: Amount(99),
                        }],
                        remote: None,
                        fee: Amount(1),
                        valid_for_blocks: 8,
                        valid_through: None,
                    },
                    old,
                )
                .unwrap();
            let signed = wallet
                .sign(
                    &h.node,
                    prepared.draft,
                    &h.root.join("owner-key.json"),
                    prepared.review_commitment,
                    old,
                )
                .unwrap();
            owner_head = signed.wallet_head;
            owner = Some(wallet);
            signed.commands
        } else {
            vec![]
        };
        let snapshot = certify(&mut h, commands);
        if height == 1 {
            initial_certificate = Some(snapshot.clone());
        }
        h.node.finalize(snapshot).unwrap();
        if height % 8 == 0 || height == 65 {
            println!("paged-integration native_height={height} actual_signer_records={:?} active_snapshots={} elapsed={:.3}",
                h.agents.iter().map(Agent::record_count).collect::<Vec<_>>(),h.node.evidence.snapshots.len(),started.elapsed().as_secs_f64());
        }
    }
    assert_eq!(h.node.evidence.snapshots.len(), 64);
    assert!(h
        .node
        .evidence
        .snapshot(initial_certificate.unwrap().statement.id().unwrap())
        .is_err());
    assert!(h.agents.iter().all(|a| a.record_count() > 128));
    owner.as_ref().unwrap().view(&h.node, owner_head).unwrap();
    // A new original timeout's publication fails deliberately. No caller head
    // advances; exact keyless recovery uses only this newly retained response.
    let request = Request::Timeout {
        context: Context::current(&h.node).unwrap(),
        round: 0,
    };
    let previous = h.heads[0];
    let before = inventory(&h.root);
    assert!(h.agents[0]
        .sign(&h.node, request.clone(), None, Hash([8; 32]))
        .is_err());
    assert_eq!(inventory(&h.root), before);
    h.agents[0].interrupt_publication(0);
    assert!(h.agents[0]
        .sign(
            &h.node,
            request.clone(),
            Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
            previous
        )
        .is_err());
    h.agents.clear();
    let recovered = Agent::recover_response(
        &h.root.join(format!("signer-{}", h.seeds[0])),
        &h.node,
        request,
        previous,
    )
    .unwrap();
    retain(&h.root, 0, recovered.head);
    h.heads[0] = recovered.head;
    let pins = Pins {
        currency: h.node.trust.currency().unwrap(),
        native: h.node.storage_head().unwrap(),
        seeds: h.seeds.clone(),
        signers: h.heads.clone(),
        wallet: owner_head,
    };
    crate::keystore::private_create(
        &h.root.join("integration-pins.json"),
        &serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let root = h.root.clone();
    drop(owner);
    drop(h);
    let output = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::regional_bft::paged_integration::paged_native_integration_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_PAGED_INTEGRATION_COLD_ROOT", &root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fresh-process complete cold failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
    println!("paged-integration finite_complete height65 actual_signatures585 wallet99_mature=true actual_sigkill=false full_fault=false elapsed={:.3}",started.elapsed().as_secs_f64());
}
