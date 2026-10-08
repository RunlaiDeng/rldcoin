//! Actual durable destination voters/owner under fresh no-value origin profile.
use super::body_witness_tests::replay;
use super::continuation_tests::inventory;
use super::export_archive_tests::source_fixture_with_profile;
use super::*;
use crate::bft::{Agent, Certificate, Context, Message, Phase, Quorum, Request};
use crate::tests::public;
use std::process::Command as Process;

struct Voters {
    agents: Vec<Agent>,
    seeds: Vec<u8>,
    heads: Vec<Hash>,
}
fn retain(root: &Path, name: &str, head: Hash) {
    let next = root.join(format!("{name}.next"));
    crate::keystore::private_create(&next, &head.0).unwrap();
    fs::rename(next, root.join(format!("{name}.head"))).unwrap();
    fs::File::open(root).unwrap().sync_all().unwrap();
}
fn sign(
    voters: &mut Voters,
    root: &Path,
    node: &Store,
    n: usize,
    request: Request,
) -> crate::bft::Signed {
    assert_eq!(
        fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
        voters.heads[n].0
    );
    let signed = voters.agents[n]
        .sign(
            node,
            request,
            Some(&root.join(format!("key-{}.json", voters.seeds[n]))),
            voters.heads[n],
        )
        .unwrap();
    retain(root, &format!("caller-{n}"), signed.head);
    voters.heads[n] = signed.head;
    signed
}
fn certify(voters: &mut Voters, root: &Path, node: &Store, commands: Vec<Command>) -> Snapshot {
    let snapshot = node.bft_candidate(commands, public(10)).unwrap();
    let context = Context::current(node).unwrap();
    let keys = voters.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let leader = crate::bft::leader(&context, 0, &keys).unwrap();
    let n = keys.iter().position(|key| *key == leader).unwrap();
    let Message::Proposal(proposal) = sign(
        voters,
        root,
        node,
        n,
        Request::Propose {
            round: 0,
            snapshot: Box::new(snapshot),
            timeout: None,
        },
    )
    .message
    else {
        panic!("real proposal")
    };
    let mut votes = vec![];
    for n in 0..3 {
        let Message::Vote(vote) =
            sign(voters, root, node, n, Request::Prepare(proposal.clone())).message
        else {
            panic!("real prepare")
        };
        votes.push(*vote);
    }
    let prepared = Quorum::combine(votes, &node.trust, &node.evidence).unwrap();
    assert_eq!(prepared.phase, Phase::Prepare);
    assert_eq!(prepared.votes.len(), 3);
    let mut votes = vec![];
    for n in 0..3 {
        let Message::Vote(vote) = sign(
            voters,
            root,
            node,
            n,
            Request::Commit {
                proposal: proposal.clone(),
                prepared: prepared.clone(),
            },
        )
        .message
        else {
            panic!("real commit")
        };
        votes.push(*vote);
    }
    let committed = Quorum::combine(votes, &node.trust, &node.evidence).unwrap();
    assert_eq!(committed.votes.len(), 3);
    let mut snapshot = *proposal.snapshot;
    snapshot.bft = Some(Certificate {
        prepared,
        committed,
    });
    snapshot
}

#[derive(Serialize, Deserialize)]
struct Pins {
    currency: Hash,
    head: Hash,
    state: Hash,
    export: Hash,
    signers: Vec<(u8, Hash)>,
    owner_head: Hash,
}
#[test]
#[ignore = "fresh custody parent passes independently retained Native/caller/owner pins"]
fn complete_origin_custody_cold_child() {
    let root = PathBuf::from(std::env::var_os("RLD_ORIGIN_CUSTODY_CHILD").unwrap());
    let pins: Pins =
        serde_json::from_slice(&fs::read(root.join("custody-pins.json")).unwrap()).unwrap();
    let before = inventory(&root);
    let node = Store::open_pinned(
        &root.join("custody-destination"),
        &public(1),
        pins.currency,
        pins.head,
    )
    .unwrap();
    assert_eq!(node.chain.height(), 4);
    assert_eq!(node.chain.ledger.root().unwrap(), pins.state);
    assert!(node.chain.ledger.imports.contains_key(&pins.export));
    assert!(node.complete_origin_pending_imports().unwrap().is_empty());
    for (n, (seed, head)) in pins.signers.iter().enumerate() {
        let agent = Agent::open(&root.join(format!("signer-{seed}")), &node).unwrap();
        assert_eq!(agent.head().unwrap(), *head);
        assert_eq!(
            fs::read(root.join(format!("caller-{n}.head"))).unwrap(),
            head.0
        );
    }
    let owner = crate::wallet_agent::Agent::open(&root.join("recipient-wallet"), &node).unwrap();
    owner.view(&node, pins.owner_head).unwrap();
    assert_eq!(
        fs::read(root.join("owner-caller.head")).unwrap(),
        pins.owner_head.0
    );
    assert_eq!(inventory(&root), before);
}

#[test]
fn complete_origin_cli_pending_real_three_of_four_owner_maturity_and_cold() {
    let (header, source, root, _, records, export) =
        source_fixture_with_profile(80, 16, crate::paged_bft::ORIGIN_HISTORY_RULES);
    let pin = source.trust.currency().unwrap();
    let destination = source.trust.named("proxima").unwrap();
    let proof = CompleteOriginHistory {
        source: header.region,
        destination,
        export,
        snapshots: records
            .into_iter()
            .map(|record| {
                let Record::Certified(snapshot) = record else {
                    panic!("certified source fixture")
                };
                *snapshot
            })
            .collect(),
    };
    let node = Store::create(
        &root.join("custody-destination"),
        header.bootstrap.clone(),
        destination,
        &public(1),
        pin,
    )
    .unwrap();
    assert!(node.complete_origin_pending_imports().unwrap().is_empty());
    let head = node.storage_head().unwrap();
    drop(node);
    let proof_file = root.join("complete-origin-proof.json");
    fs::write(&proof_file, serde_json::to_vec(&proof).unwrap()).unwrap();
    let cli = PathBuf::from(
        std::env::var_os("RLD_EXPORT_ARCHIVE_CANDIDATE_CLI").expect("bounded actual CLI provider"),
    );
    let invoke = |action: &str, expected: Hash| {
        let mut process = Process::new(&cli);
        process
            .args(["--dir"])
            .arg(root.join("custody-destination"))
            .args([
                "--authority",
                &public(1),
                "--currency",
                &pin.to_hex(),
                action,
            ]);
        if action == "complete-origin-history-accept" {
            process
                .arg("--file")
                .arg(&proof_file)
                .args(["--expected-head", &expected.to_hex()]);
        }
        process
            .current_dir(std::env::current_dir().unwrap())
            .output()
            .unwrap()
    };
    let before = inventory(&root);
    let wrong = invoke("complete-origin-history-accept", Hash([9; 32]));
    assert!(!wrong.status.success() && wrong.stdout.is_empty());
    assert_eq!(inventory(&root), before);
    let accepted = invoke("complete-origin-history-accept", head);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(response["verified"], true);
    for name in [
        "ledger_changed",
        "import_accepted",
        "recipient_maturity_qualified",
        "owner_signing_authority",
        "remote_current_state_known",
    ] {
        assert_eq!(response[name], false);
    }
    let pending_cli = invoke("bft-pending-imports", head);
    assert!(pending_cli.status.success());
    let pending_cli: Vec<Command> = serde_json::from_slice(&pending_cli.stdout).unwrap();
    assert_eq!(pending_cli.len(), 1);
    let mut node = Store::open_pinned(
        &root.join("custody-destination"),
        &public(1),
        pin,
        serde_json::from_value(response["storage_head"].clone()).unwrap(),
    )
    .unwrap();
    let pending = node.complete_origin_pending_imports().unwrap();
    assert_eq!(pending, pending_cli);
    assert_eq!(pending.len(), 1);
    assert_eq!(node.chain.height(), 0);
    assert!(node.chain.ledger.coins.is_empty());
    let mut seeds = vec![2, 3, 4, 5];
    seeds.sort_by_key(|seed| public(*seed));
    let mut voters = Voters {
        agents: vec![],
        seeds,
        heads: vec![],
    };
    for (n, seed) in voters.seeds.iter().enumerate() {
        crate::keystore::private_create(
            &root.join(format!("key-{seed}.json")),
            &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([*seed;32])}))
                .unwrap(),
        )
        .unwrap();
        let agent =
            Agent::create(&root.join(format!("signer-{seed}")), &node, public(*seed)).unwrap();
        let head = agent.head().unwrap();
        retain(&root, &format!("caller-{n}"), head);
        voters.heads.push(head);
        voters.agents.push(agent);
    }
    let certificate = certify(&mut voters, &root, &node, pending);
    node.finalize(certificate).unwrap();
    assert!(node.complete_origin_pending_imports().unwrap().is_empty());
    let mut owner =
        crate::wallet_agent::Agent::create(&root.join("recipient-wallet"), &node, public(11))
            .unwrap();
    let initial_owner = owner.journal.head().unwrap();
    retain(&root, "owner-caller", initial_owner);
    crate::keystore::private_create(
        &root.join("recipient-key.json"),
        &serde_json::to_vec(&serde_json::json!({"secret_key":hex::encode([11;32])})).unwrap(),
    )
    .unwrap();
    let request = crate::wallet::Request {
        owner: public(11),
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: public(12),
            amount: Amount(98),
        }],
        remote: None,
        fee: Amount(1),
        valid_for_blocks: 8,
        valid_through: None,
    };
    let immature = inventory(&root);
    assert!(owner
        .prepare(&node, request.clone(), initial_owner)
        .is_err());
    assert_eq!(inventory(&root), immature);
    for _ in 0..2 {
        let certificate = certify(&mut voters, &root, &node, vec![]);
        node.finalize(certificate).unwrap();
    }
    let receipt = crate::wallet::receipt(
        &node,
        crate::wallet::ReceiptExpectation {
            currency: pin,
            source: header.region,
            destination,
            export,
            recipient: public(11),
            net_amount: Amount(99),
        },
    )
    .unwrap();
    assert!(receipt.original_output_spendable_now);
    let prepared = owner.prepare(&node, request, initial_owner).unwrap();
    let signed = owner
        .sign(
            &node,
            prepared.draft,
            &root.join("recipient-key.json"),
            prepared.review_commitment,
            initial_owner,
        )
        .unwrap();
    retain(&root, "owner-caller", signed.wallet_head);
    let certificate = certify(&mut voters, &root, &node, signed.commands);
    node.finalize(certificate).unwrap();
    owner.view(&node, signed.wallet_head).unwrap();
    assert_eq!(
        conservation(&[source.chain.clone(), node.chain.clone()])
            .unwrap()
            .2,
        Amount::ZERO
    );
    let pins = Pins {
        currency: pin,
        head: node.storage_head().unwrap(),
        state: node.chain.ledger.root().unwrap(),
        export,
        signers: voters.seeds.iter().copied().zip(voters.heads).collect(),
        owner_head: signed.wallet_head,
    };
    drop(voters.agents);
    drop(owner);
    drop(node);
    fs::write(
        root.join("custody-pins.json"),
        serde_json::to_vec(&pins).unwrap(),
    )
    .unwrap();
    let before = inventory(&root);
    let result = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage::paged::origin_custody_tests::complete_origin_custody_cold_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RLD_ORIGIN_CUSTODY_CHILD", &root)
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(inventory(&root), before);
    // Inspecting a source replay never substitutes for its original signing custody.
    assert_eq!(replay(&header).chain.height(), 0);
}
