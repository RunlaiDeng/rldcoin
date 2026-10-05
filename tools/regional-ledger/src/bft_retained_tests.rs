use super::*;
use crate::retained_pages::{Purpose, Scope, Stream};
use std::collections::BTreeMap;

type Inventory = BTreeMap<PathBuf, (Hash, u64, u32, u128)>;
fn inventory(root: &Path) -> Inventory {
    fn walk(path: &Path, rows: &mut Inventory) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                walk(&path, rows);
            } else {
                #[cfg(unix)]
                use std::os::unix::fs::MetadataExt;
                #[cfg(unix)]
                let mode = meta.mode();
                #[cfg(not(unix))]
                let mode = 0;
                rows.insert(
                    path.clone(),
                    (
                        Hash(Sha256::digest(fs::read(&path).unwrap()).into()),
                        meta.len(),
                        mode,
                        meta.modified()
                            .unwrap()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos(),
                    ),
                );
            }
        }
    }
    let mut rows = BTreeMap::new();
    walk(root, &mut rows);
    rows
}
fn state_bytes(state: &bft::State) -> Vec<u8> {
    serde_json::to_vec(state).unwrap()
}
fn retain(dir: &Path, scope: &Scope, records: &[bft::Record]) -> Stream<bft::Record> {
    let mut stream = Stream::create(dir, scope.clone()).unwrap();
    for batch in records.chunks(history::PAGE_EVENTS) {
        stream.append(batch, stream.storage_head()).unwrap();
    }
    stream
}
#[test]
fn ordinary_agent_and_complete_pages_share_native_replay_without_custody_changes() {
    let started = std::time::Instant::now();
    let mut h = Harness::new();
    h.retain = true;
    for height in 1..=8 {
        let commands = if height == 4 {
            let input = *h
                .node
                .chain
                .ledger
                .coins
                .iter()
                .find(|(_, c)| c.mature <= 3 && c.payment.owner == public(10))
                .unwrap()
                .0;
            vec![Command::Spend(Box::new(intent(
                &h.node.chain,
                &h.node.trust,
                vec![input],
                vec![Payment {
                    owner: public(11),
                    amount: Amount(99),
                }],
                None,
                None,
                1,
                0,
                &[10],
            )))]
        } else {
            vec![]
        };
        let snapshot = h.node.bft_candidate(commands, public(10)).unwrap();
        let p = h.proposal(0, None, snapshot);
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        let s = h.commit(&p, &q, &[0, 1, 2, 3]);
        h.node.finalize(s).unwrap();
    }
    assert_eq!(h.node.chain.height(), 8);
    assert_eq!(h.node.chain.ledger.minted, Amount(300));
    assert!(h
        .node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(11) && c.payment.amount == Amount(99) && c.mature <= 8));
    println!(
        "native-retained-replay phase=real-owner-payment-certified height=8 elapsed={:.3}",
        started.elapsed().as_secs_f64()
    );
    let before = inventory(&h.root);
    let mut headers = Vec::new();
    let mut storage_heads = Vec::new();
    for (n, agent) in h.agents.iter().enumerate() {
        bft::compare_all_prefixes(&agent.journal);
        let mut header = agent.journal.clone();
        header.records.clear();
        let scope = Scope::bind(
            &h.node.trust,
            h.node.chain.region,
            Purpose::BftSigner(header.binding.key.clone()),
            header.head().unwrap(),
        )
        .unwrap();
        let path = h.root.join(format!("mirror-{n}"));
        let stream = retain(&path, &scope, &agent.journal.records);
        assert!(agent.journal.records.len() >= 16);
        assert!(!fs::read_dir(path.join("pages"))
            .unwrap()
            .collect::<Vec<_>>()
            .is_empty());
        let storage_head = stream.storage_head();
        let selected = header
            .state_from_retained(&h.node, &stream, storage_head, h.heads[n])
            .unwrap();
        assert_eq!(
            state_bytes(&selected),
            state_bytes(&agent.journal.state(&h.node).unwrap())
        );
        assert!(selected.lock.is_some());
        assert!(header
            .state_from_retained(&h.node, &stream, storage_head, header.head().unwrap())
            .is_err());
        assert!(header
            .state_from_retained(&h.node, &stream, header.head().unwrap(), h.heads[n])
            .is_err());
        headers.push(header);
        storage_heads.push(storage_head);
    }
    // A structurally correct mirror has a bad signature in its last complete
    // record, after the complete first page. Full native auth must reject it.
    let mut bad = h.agents[0].journal.clone();
    assert!(bad.records.len() > 16);
    match &mut bad.records.last_mut().unwrap().message {
        Message::Vote(v) => v.approval.signature = "00".repeat(64),
        Message::Proposal(p) => p.leader.signature = "00".repeat(64),
        _ => panic!("ordinary last record must be a proposal or vote"),
    }
    let scope = Scope::bind(
        &h.node.trust,
        h.node.chain.region,
        Purpose::BftSigner(headers[0].binding.key.clone()),
        headers[0].head().unwrap(),
    )
    .unwrap();
    let stream = retain(&h.root.join("bad-signature-mirror"), &scope, &bad.records);
    let error = headers[0]
        .state_from_retained(&h.node, &stream, stream.storage_head(), bad.head().unwrap())
        .err()
        .unwrap();
    assert!(
        !error.contains("head differs") && !error.contains("stream"),
        "{error}"
    );
    assert!(bad.state(&h.node).is_err());
    let alien = Scope::bind(
        &h.node.trust,
        h.node.chain.region,
        Purpose::Ledger,
        headers[0].head().unwrap(),
    )
    .unwrap();
    let wrong = retain(
        &h.root.join("wrong-purpose-mirror"),
        &alien,
        &h.agents[0].journal.records,
    );
    assert!(headers[0]
        .state_from_retained(&h.node, &wrong, wrong.storage_head(), h.heads[0])
        .unwrap_err()
        .contains("consumer scope"));
    let after = inventory(&h.root);
    for (path, value) in &before {
        assert_eq!(
            Some(value),
            after.get(path),
            "native/caller bytes mutated: {}",
            path.display()
        );
    }
    let root = h.root.clone();
    let pin = h.node.trust.currency().unwrap();
    let native_storage_head = history::manifest(&root.join("node"))
        .unwrap()
        .head()
        .unwrap();
    let heads = h.heads.clone();
    let seeds = h.seeds.clone();
    let ledger = h.node.chain.ledger.clone();
    drop(stream);
    drop(wrong);
    drop(h); // Release native locks without deleting the fresh private fixture.
    let node =
        Store::open_pinned(&root.join("node"), &public(1), pin, native_storage_head).unwrap();
    assert_eq!(node.chain.ledger, ledger);
    for n in 0..4 {
        let agent = Agent::open(&root.join(format!("signer-{}", seeds[n])), &node).unwrap();
        assert_eq!(agent.journal.head().unwrap(), heads[n]);
        let scope = Scope::bind(
            &node.trust,
            node.chain.region,
            Purpose::BftSigner(headers[n].binding.key.clone()),
            headers[n].head().unwrap(),
        )
        .unwrap();
        let stream =
            Stream::open(&root.join(format!("mirror-{n}")), &scope, storage_heads[n]).unwrap();
        assert_eq!(
            state_bytes(
                &headers[n]
                    .state_from_retained(&node, &stream, storage_heads[n], heads[n])
                    .unwrap()
            ),
            state_bytes(&agent.journal.state(&node).unwrap())
        );
    }
    assert_eq!(after, inventory(&root));
    println!("native-retained-replay phase=complete fixture={} height=8 owner_payment=99 sealed_pages=4 native_paged_signing=false elapsed={:.3}",
        root.display(), started.elapsed().as_secs_f64());
}
