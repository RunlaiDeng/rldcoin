//! Public no-value inputs exercise real Native replay, caller heads and signer locks.
use super::*;
use crate::tests::{public, signature};
use crate::{Amount, Approval, Intent, Payment, SignedIntent};

#[path = "work_tests.rs"]
mod work_tests;

struct Fixture {
    root: PathBuf,
    source: Store,
    node: Store,
    actors: Vec<Runtime>,
    seeds: Vec<u8>,
    raw: Vec<u8>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = directory(
            &fs::canonicalize(std::env::temp_dir())
                .map_err(|e| e.to_string())?
                .join(format!("rld-rust-import-{}", random()?)),
        )?;
        let mut genesis = crate::tests::bootstrap();
        genesis.admissions[1].rules = consensus::RULES.into();
        genesis.admissions[1].signature = signature(1, &genesis.admissions[1].bytes()?);
        let currency = genesis.currency.id()?;
        let region = genesis.admissions[1].id()?;
        let mut source = Store::create(
            &root.join("source"),
            genesis.clone(),
            genesis.admissions[0].id()?,
            &public(1),
            currency,
        )?;
        for _ in 0..3 {
            let mut block = source.template(vec![], public(10))?;
            crate::mine(&mut block)?;
            source.accept(block)?;
        }
        let mut seeds = (2u8..6).collect::<Vec<_>>();
        seeds.sort_by_key(|s| public(*s));
        source_checkpoint(&mut source, &seeds)?;
        let input = *source
            .chain
            .ledger
            .coins
            .iter()
            .find(|(_, c)| c.payment.owner == public(10) && c.mature <= 3)
            .ok_or("source mature fixture coin missing")?
            .0;
        let intent = Intent {
            currency,
            region: source.chain.region,
            inputs: vec![input],
            outputs: vec![],
            fee: Amount(1),
            destination: Some(region),
            remote: Some(Payment {
                owner: public(11),
                amount: Amount(99),
            }),
            destination_fee: Amount(1),
            valid_through: 12,
        };
        let export = intent.id()?;
        let signed = SignedIntent {
            approvals: vec![Approval {
                key: public(10),
                signature: signature(10, &intent.bytes()?),
            }],
            intent,
        };
        let mut block = source.template(vec![Command::Spend(Box::new(signed))], public(10))?;
        crate::mine(&mut block)?;
        source.accept(block)?;
        source_checkpoint(&mut source, &seeds)?;
        let raw = source.contact_export(export)?;
        let node = Store::create(
            &root.join("recipient"),
            genesis,
            region,
            &public(1),
            currency,
        )?;
        let mut transports = Vec::new();
        let mut ids = Vec::new();
        for n in 0..4 {
            let transport = root.join(format!("transport-{n}"));
            let identity = initialize(
                &transport,
                &currency.to_hex(),
                &region.to_hex(),
                "public-no-value-import-test",
            )?;
            ids.push(
                identity["node_id"]
                    .as_str()
                    .ok_or("fixture peer")?
                    .to_owned(),
            );
            transports
                .push(json!({"format":MESH,"network":currency,"state":transport,"contacts":[]}));
        }
        let mut actors = Vec::new();
        for n in 0..4 {
            let signer = root.join(format!("signer-{n}"));
            let agent = consensus::Agent::create(&signer, &node, public(seeds[n]))?;
            let state = bft_client::State {
                format: bft_client::FORMAT.into(),
                binding: agent.journal.binding.clone(),
                head: agent.head()?,
                pending: None,
                outbox: None,
            };
            drop(agent);
            let caller = directory(&root.join(format!("caller-{n}")))?.join("head.json");
            crate::keystore::private_create(&caller, &files::canonical(&state)?)?;
            let key = root.join(format!("key-{n}.json"));
            crate::keystore::private_create(
                &key,
                &serde_json::to_vec(&json!({"secret_key":hex::encode([seeds[n];32])}))
                    .map_err(|e| e.to_string())?,
            )?;
            let config = json!({"format":bft_client::FORMAT,"state":directory(&root.join(format!("runtime-{n}")))?,
                "signer_dir":signer,"head_file":caller,"key_file":key,"key":public(seeds[n]),"miner":public(12),
                "validators":seeds.iter().enumerate().map(|(p,s)|json!({"key":public(*s),"node_id":ids[p]})).collect::<Vec<_>>(),
                "block_interval":0.5,"round_timeout":5.0,"stop_height":4});
            let path = root.join(format!("config-{n}.json"));
            atomic(&path, &config, 64 * 1024)?;
            actors.push(Runtime::open(&path, &node, &transports[n])?);
        }
        Ok(Self {
            root,
            source,
            node,
            actors,
            seeds,
            raw,
        })
    }

    fn candidate(&self) -> Result<Snapshot> {
        self.actors[0].candidate(&self.node, &consensus::Context::current(&self.node)?, None)
    }

    fn sign(&mut self, n: usize, request: consensus::Request) -> Result<consensus::Message> {
        let before = self.actors[n]
            .archive
            .runtime
            .messages
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        self.actors[n].sign(&self.node, request)?;
        let mut created = self.actors[n]
            .archive
            .runtime
            .messages
            .iter()
            .filter(|(id, _)| !before.contains(id));
        let (_, record) = created.next().ok_or("missing durable native response")?;
        require(created.next().is_none(), "ambiguous native response")?;
        match serde_json::from_value(record.body.clone()).map_err(|e| e.to_string())? {
            net::Body::Signed(message) => Ok(*message),
            _ => Err("response is not a native signed message".into()),
        }
    }

    fn finalize(&mut self, snapshot: Snapshot) -> Result<()> {
        let context = consensus::Context::current(&self.node)?;
        let keys = self.seeds.iter().copied().map(public).collect::<Vec<_>>();
        let leader = consensus::leader(&context, 0, &keys)?;
        let n = keys
            .iter()
            .position(|k| k == &leader)
            .ok_or("fixture leader")?;
        let consensus::Message::Proposal(proposal) = self.sign(
            n,
            consensus::Request::Propose {
                round: 0,
                timeout: None,
                snapshot: Box::new(snapshot),
            },
        )?
        else {
            return Err("fixture proposal response".into());
        };
        let mut votes = Vec::new();
        for n in 0..3 {
            let consensus::Message::Vote(vote) =
                self.sign(n, consensus::Request::Prepare(proposal.clone()))?
            else {
                return Err("fixture prepare response".into());
            };
            votes.push(*vote);
        }
        let prepared = consensus::Quorum::combine(votes, &self.node.trust, &self.node.evidence)?;
        let mut votes = Vec::new();
        for n in 0..3 {
            let consensus::Message::Vote(vote) = self.sign(
                n,
                consensus::Request::Commit {
                    proposal: proposal.clone(),
                    prepared: prepared.clone(),
                },
            )?
            else {
                return Err("fixture commit response".into());
            };
            votes.push(*vote);
        }
        let committed = consensus::Quorum::combine(votes, &self.node.trust, &self.node.evidence)?;
        let mut snapshot = *proposal.snapshot;
        snapshot.bft = Some(consensus::Certificate {
            prepared,
            committed,
        });
        self.node.finalize(snapshot)?;
        Ok(())
    }
}

fn source_checkpoint(source: &mut Store, seeds: &[u8]) -> Result<()> {
    let statement = source.chain.statement(&source.trust)?;
    let raw = statement.bytes()?;
    source.finalize(Snapshot {
        base: source.chain.snapshot_base(),
        approvals: seeds
            .iter()
            .map(|s| Approval {
                key: public(*s),
                signature: signature(*s, &raw),
            })
            .collect(),
        statement,
        blocks: source.chain.blocks.clone(),
        bft: None,
        epochs: vec![],
    })?;
    Ok(())
}

#[test]
fn new_owner_submission_first_carriage_precedes_retained_historical_votes() {
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh first-carriage fixture: {}", f.root.display());
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..3 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let input = *f
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(11) && c.mature <= 3)
        .unwrap()
        .0;
    let intent = Intent {
        currency: f.node.trust.currency().unwrap(),
        region: f.node.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(13),
            amount: Amount(98),
        }],
        fee: Amount::ZERO,
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 4,
    };
    let commands = vec![Command::Spend(Box::new(SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    }))];
    let body = serde_json::to_value(net::Body::Submission(commands.clone())).unwrap();
    f.node.bft_submit(commands).unwrap();
    // This stopped component observes submission carriage without proposing a
    // fourth block. All three predecessors used real Native certificates.
    f.actors[0].config.stop_height = 3;
    f.actors[0].tick(&mut f.node).unwrap();
    let local = f.actors[0]
        .archive
        .runtime
        .messages
        .iter()
        .filter(|(_, r)| r.local)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let submission = hash(&body).unwrap();
    assert!(local.len() > 4);
    let position = local.iter().position(|id| *id == submission).unwrap();
    // A permitted cursor starts at historical bodies, with the new request
    // immediately behind the ordinary four-item page.
    f.actors[0].archive.runtime.cursor = ((position + 1) % local.len()) as u64;
    let validators = f.actors[0]
        .config
        .validators
        .iter()
        .map(|v| v.node_id.clone())
        .collect::<Vec<_>>();
    let currency = f.node.trust.currency().unwrap();
    let transport = json!({"format":MESH,"network":currency,"state":f.root.join("transport-0"),
        "contacts":validators.iter().skip(1).enumerate().map(|(n, peer)|json!({"peer":peer,
            "inbox":f.root.join(format!("inbox-{n}")),"outbox":f.root.join(format!("outbox-{n}"))})).collect::<Vec<_>>()});
    let head = f.node.storage_head().unwrap();
    let deferred = local[(position + 4) % local.len()];
    let deferred_frame = f.actors[0].carriage_frame(deferred).unwrap().message_id;
    let request_frame = f.actors[0].carriage_frame(submission).unwrap().message_id;
    f.actors[0].broadcast(&transport).unwrap();
    let mut packets = Vec::new();
    for peer in validators.iter().skip(1) {
        let bundle = Node::open(&transport).unwrap().prepare(peer).unwrap();
        let transits = bundle["body"]["transits"].as_array().unwrap();
        assert!(transits.len() <= 4);
        let mut found = false;
        for transit in transits {
            let raw = STANDARD
                .decode(transit["packet"]["body"]["frame"].as_str().unwrap())
                .unwrap();
            let (_, payload) = crate::contact_frame::inspect_bytes(
                &raw,
                None,
                None,
                crate::contact::MAX_PAYLOAD,
                crate::contact::MAX_FRAME,
            )
            .unwrap();
            let envelope = crate::bft_client::decode::<net::WireEnvelope>(&payload)
                .unwrap()
                .expand()
                .unwrap();
            envelope.verify(&f.node).unwrap();
            found |= serde_json::to_value(envelope.body).unwrap() == body;
        }
        assert!(found, "first carriage omitted the new Native owner request");
        let mesh = Node::open(&transport).unwrap();
        packets.push(mesh.originated_frame(request_frame, peer).unwrap().unwrap());
        assert!(mesh
            .originated_frame(deferred_frame, peer)
            .unwrap()
            .is_none());
    }
    // A cold authenticated mesh observation retires first-origination priority,
    // even without any peer receipt. The normal historical page is eligible.
    f.actors[0].archive.runtime.cursor = ((position + 1) % local.len()) as u64;
    f.actors[0].broadcast(&transport).unwrap();
    for (peer, packet) in validators.iter().skip(1).zip(packets) {
        let mesh = Node::open(&transport).unwrap();
        assert_eq!(
            mesh.originated_frame(request_frame, peer).unwrap(),
            Some(packet)
        );
        assert!(mesh
            .originated_frame(deferred_frame, peer)
            .unwrap()
            .is_some());
    }
    assert_eq!(f.node.storage_head().unwrap(), head);
    assert!(f.node.chain.ledger.coins.contains_key(&input));
    assert_eq!(f.node.chain.height(), 3);
    let root = f.root.clone();
    drop(f.actors);
    drop(f.node);
    let cold = Store::open_pinned(&root.join("recipient"), &public(1), currency, head).unwrap();
    assert!(cold.chain.ledger.coins.contains_key(&input));
    assert_eq!(cold.chain.height(), 3);
    drop(cold);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_rust_candidate_imports_retained_proof_then_finalizes_recipient_spend() {
    let mut f = Fixture::new().unwrap();
    let initial_head = f.node.storage_head().unwrap();
    let (_, mut altered) = Frame::unpack(&f.raw).unwrap();
    altered.evidence.snapshots.last_mut().unwrap().approvals[0].signature = "00".repeat(64);
    let altered = Frame::pack(&altered).unwrap();
    assert!(f.node.contact_apply(&altered, None).is_err());
    let (_, mut missing) = Frame::unpack(&f.raw).unwrap();
    missing.evidence.snapshots.clear();
    let missing = Frame::pack(&missing).unwrap();
    assert!(f.node.contact_apply(&missing, None).is_err());
    assert_eq!(f.node.storage_head().unwrap(), initial_head);
    assert!(f.node.journal.contact_records.is_empty());
    let status = f.node.contact_apply(&f.raw, None).unwrap();
    let message = status.message_id;
    assert!(!status.import_accepted && !status.original_recipient_output_spendable_now);
    assert_eq!(f.node.chain.height(), 0);
    let candidate = f.candidate().unwrap();
    assert!(
        matches!(candidate.blocks.last().unwrap().commands.as_slice(), [Command::Import { export, .. }] if *export == status.export)
    );
    // Candidate construction cannot consume or credit anything.
    assert!(f.node.chain.ledger.imports.is_empty());
    assert!(f.node.chain.ledger.coins.is_empty());
    let mut bad = candidate.clone();
    if let Command::Import { snapshot, .. } = &mut bad.blocks.last_mut().unwrap().commands[0] {
        *snapshot = Hash::ZERO;
    }
    let head = f.node.storage_head().unwrap();
    assert!(f.node.finalize(candidate.clone()).is_err());
    assert!(f.node.finalize(bad).is_err());
    assert_eq!(f.node.storage_head().unwrap(), head);
    f.finalize(candidate).unwrap();
    let imported = f.node.contact_status(message).unwrap();
    assert!(imported.import_accepted && !imported.original_recipient_output_spendable_now);
    assert_eq!(imported.recipient_mature_height, Some(3));
    for _ in 0..2 {
        f.node.contact_apply(&f.raw, None).unwrap();
        let candidate = f.candidate().unwrap();
        assert!(candidate.blocks.last().unwrap().commands.is_empty());
        f.finalize(candidate).unwrap();
    }
    let status = f.node.contact_status(message).unwrap();
    assert!(status.original_recipient_output_spendable_now && !status.quarantined);
    assert_eq!(status.original_recipient_output_remaining, Amount(98));
    let input = *f
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(11))
        .unwrap()
        .0;
    let intent = Intent {
        currency: f.node.trust.currency().unwrap(),
        region: f.node.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(13),
            amount: Amount(98),
        }],
        fee: Amount::ZERO,
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 4,
    };
    let signed = SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    };
    f.node
        .bft_submit(vec![Command::Spend(Box::new(signed))])
        .unwrap();
    f.actors[0].submissions(&f.node).unwrap();
    assert!(f.node.chain.ledger.coins.contains_key(&input));
    let candidate = f.candidate().unwrap();
    assert!(matches!(
        candidate.blocks.last().unwrap().commands.as_slice(),
        [Command::Spend(_)]
    ));
    f.finalize(candidate).unwrap();
    assert!(!f.node.chain.ledger.coins.contains_key(&input));
    assert!(f
        .node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(13) && c.payment.amount == Amount(98)));
    assert_eq!(f.node.chain.ledger.imports.len(), 1);
    assert_eq!(f.node.chain.ledger.minted, Amount::ZERO);
    assert!(f
        .candidate()
        .unwrap()
        .blocks
        .last()
        .unwrap()
        .commands
        .is_empty());
    let currency = f.node.trust.currency().unwrap();
    let head = f.node.storage_head().unwrap();
    let ledger = f.node.chain.ledger.root().unwrap();
    let root = f.root.clone();
    drop(f.actors);
    drop(f.node);
    let cold = Store::open_pinned(&root.join("recipient"), &public(1), currency, head).unwrap();
    assert_eq!(cold.chain.ledger.root().unwrap(), ledger);
    assert_eq!(cold.chain.ledger.imports.len(), 1);
    assert_eq!(cold.chain.height(), 4);
    for (n, seed) in f.seeds.iter().enumerate() {
        let caller = bft_client::Client::lock(
            &root.join(format!("caller-{n}/head.json")),
            &root.join(format!("signer-{n}")),
            public(*seed),
            bft_client::FORMAT.into(),
            &cold,
        )
        .unwrap();
        let state = caller.read().unwrap();
        let (_, status) =
            consensus::Agent::inspect_with_status(&root.join(format!("signer-{n}")), &cold)
                .unwrap();
        assert_eq!(status.head, state.head);
        assert!(state.pending.is_none() && state.outbox.is_none());
    }
    let third = crate::Chain::new(cold.trust.named("andromeda").unwrap(), &cold.trust).unwrap();
    crate::conservation(&[f.source.chain.clone(), cold.chain.clone(), third]).unwrap();
    drop(cold);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}

#[path = "wallet_queue_tests.rs"]
mod wallet_queue_tests;

#[test]
fn complete_prepare_quorum_after_timeout_cannot_first_sign_old_commit() {
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh sealed-round Native counter: {}", f.root.display());
    let native_head = f.node.storage_head().unwrap();
    let context = consensus::Context::current(&f.node).unwrap();
    let keys = f.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let leader = consensus::leader(&context, 0, &keys).unwrap();
    let leader = keys.iter().position(|key| key == &leader).unwrap();
    let candidate = f.candidate().unwrap();
    let consensus::Message::Proposal(proposal) = f
        .sign(
            leader,
            consensus::Request::Propose {
                round: 0,
                timeout: None,
                snapshot: Box::new(candidate),
            },
        )
        .unwrap()
    else {
        panic!("expected original Native proposal")
    };
    let mut votes = Vec::new();
    for n in 0..3 {
        let consensus::Message::Vote(vote) = f
            .sign(n, consensus::Request::Prepare(proposal.clone()))
            .unwrap()
        else {
            panic!("expected original Native prepare")
        };
        votes.push(*vote);
    }
    let prepared = consensus::Quorum::combine(votes, &f.node.trust, &f.node.evidence).unwrap();
    for n in 0..2 {
        f.sign(
            n,
            consensus::Request::Commit {
                proposal: proposal.clone(),
                prepared: prepared.clone(),
            },
        )
        .unwrap();
    }
    f.sign(2, consensus::Request::Timeout { context, round: 0 })
        .unwrap();
    let config = &f.actors[2].config;
    let journal_path = config.signer_dir.join("bft.json");
    let caller_before = fs::read(&config.head_file).unwrap();
    let journal_before = fs::read(&journal_path).unwrap();
    let (mut agent, status) =
        consensus::Agent::inspect_with_status(&config.signer_dir, &f.node).unwrap();
    assert_eq!(status.state.round, 1);
    assert!(status.state.prepared.is_none() && status.state.committed.is_none());
    let head = agent.head().unwrap();
    let error = agent
        .sign(
            &f.node,
            consensus::Request::Commit { proposal, prepared },
            Some(&config.key_file),
            head,
        )
        .unwrap_err();
    assert_eq!(
        error,
        "BFT commit needs own current prepare and matching prepared quorum"
    );
    assert_eq!(agent.head().unwrap(), head);
    drop(agent);
    assert_eq!(fs::read(&config.head_file).unwrap(), caller_before);
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
    assert_eq!(f.node.storage_head().unwrap(), native_head);
    assert_eq!(f.node.chain.height(), 0);
    let root = f.root.clone();
    drop(f);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_directory_turn_carries_new_native_owner_request_in_same_turn() {
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh same-turn Native owner fixture: {}", f.root.display());
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..3 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let input = *f
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(11) && c.mature <= 3)
        .unwrap()
        .0;
    let intent = Intent {
        currency: f.node.trust.currency().unwrap(),
        region: f.node.chain.region,
        inputs: vec![input],
        outputs: vec![Payment {
            owner: public(13),
            amount: Amount(98),
        }],
        fee: Amount::ZERO,
        destination: None,
        remote: None,
        destination_fee: Amount::ZERO,
        valid_through: 4,
    };
    let commands = vec![Command::Spend(Box::new(SignedIntent {
        approvals: vec![Approval {
            key: public(11),
            signature: signature(11, &intent.bytes().unwrap()),
        }],
        intent,
    }))];
    let body = serde_json::to_value(net::Body::Submission(commands.clone())).unwrap();
    f.node.bft_submit(commands).unwrap();
    let currency = f.node.trust.currency().unwrap();
    let root = f.root.clone();
    let head = f.node.storage_head().unwrap();
    drop(f.node);
    let mut runtime = Some(f.actors.remove(0));
    runtime.as_mut().unwrap().config.stop_height = 3;
    let peers = runtime
        .as_ref()
        .unwrap()
        .config
        .validators
        .iter()
        .skip(1)
        .map(|v| v.node_id.clone())
        .collect::<Vec<_>>();
    let transport = json!({"format":MESH,"network":currency,"state":root.join("transport-0"),
        "contacts":peers.iter().enumerate().map(|(n,peer)|json!({"peer":peer,"inbox":root.join(format!("same-in-{n}")),"outbox":root.join(format!("same-out-{n}"))})).collect::<Vec<_>>()});
    let options = super::super::service::Options {
        ledger: root.join("recipient"),
        authority: public(1),
        currency,
        mesh_config: None,
        bft_config: None,
        listen: "127.0.0.1:0".parse().unwrap(),
        miner: None,
        interval: 0.5,
        insecure_tcp: false,
    };
    let mut cursor = None;
    let mut seen = Vec::new();
    super::super::service::start_work_trace();
    super::super::service::directory_ledger_turn(
        &options,
        &transport,
        &mut runtime,
        &mut cursor,
        &mut seen,
    )
    .unwrap();
    let work = super::super::service::take_work_trace();
    let opens = work
        .iter()
        .filter(|event| event["phase"] == "mesh-state-decode-expand")
        .map(|event| event["calls"].as_u64().unwrap_or(1))
        .sum::<u64>();
    assert_eq!(
        opens, 2,
        "ordinary post-ledger carriage reopened the same transport image"
    );
    for n in 0..3 {
        let files = fs::read_dir(root.join(format!("same-out-{n}")))
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(files.len(), 1);
        let exchange = read(&files[0].path(), EXCHANGE_LIMIT).unwrap();
        let mut found = false;
        for t in exchange["body"]["transits"].as_array().unwrap() {
            let raw = STANDARD
                .decode(t["packet"]["body"]["frame"].as_str().unwrap())
                .unwrap();
            let (_, payload) = crate::contact_frame::inspect_bytes(
                &raw,
                None,
                None,
                crate::contact::MAX_PAYLOAD,
                crate::contact::MAX_FRAME,
            )
            .unwrap();
            let envelope = crate::bft_client::decode::<net::WireEnvelope>(&payload)
                .unwrap()
                .expand()
                .unwrap();
            found |= serde_json::to_value(envelope.body).unwrap() == body;
        }
        assert!(
            found,
            "ordinary same-turn carriage deferred the new Native owner request"
        );
    }
    let node = Store::open_inspection(&options.ledger, &public(1), currency).unwrap();
    assert_eq!(node.storage_head().unwrap(), head);
    assert!(node.chain.ledger.coins.contains_key(&input));
    drop(node);
    drop(runtime);
    drop(f.actors);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn current_native_prepare_is_carried_ahead_of_unstarted_historical_packets() {
    let mut f = Fixture::new().unwrap();
    eprintln!(
        "Fresh Native prepare carriage fixture: {}",
        f.root.display()
    );
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..3 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let context = consensus::Context::current(&f.node).unwrap();
    let keys = f.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let leader = keys
        .iter()
        .position(|key| *key == consensus::leader(&context, 0, &keys).unwrap())
        .unwrap();
    let snapshot = f.candidate().unwrap();
    let consensus::Message::Proposal(proposal) = f
        .sign(
            leader,
            consensus::Request::Propose {
                round: 0,
                timeout: None,
                snapshot: Box::new(snapshot),
            },
        )
        .unwrap()
    else {
        panic!("proposal shape")
    };
    let prepare = f.sign(0, consensus::Request::Prepare(proposal)).unwrap();
    let prepare =
        hash(&serde_json::to_value(net::Body::Signed(Box::new(prepare))).unwrap()).unwrap();
    let actor = &mut f.actors[0];
    actor.archive.runtime.height = f.node.chain.height();
    let validators = actor
        .config
        .validators
        .iter()
        .map(|v| v.node_id.clone())
        .collect::<Vec<_>>();
    let peers = validators
        .iter()
        .enumerate()
        .filter(|(n, _)| *n != 0)
        .map(|(_, id)| id.clone())
        .collect::<Vec<_>>();
    let currency = f.node.trust.currency().unwrap();
    let transport = json!({"format":MESH,"network":currency,"state":f.root.join("transport-0"),
        "contacts":peers.iter().enumerate().map(|(n,peer)|json!({"peer":peer,"inbox":f.root.join(format!("in-{n}")),"outbox":f.root.join(format!("out-{n}"))})).collect::<Vec<_>>()});
    let historical = actor
        .archive
        .runtime
        .messages
        .iter()
        .filter(|(_, r)| r.local)
        .filter_map(|(id, r)| {
            let body: net::Body = serde_json::from_value(r.body.clone()).unwrap();
            match body {
                net::Body::Signed(m) => match *m {
                    consensus::Message::Vote(v) if v.context.parent_height < 3 => Some(*id),
                    _ => None,
                },
                _ => None,
            }
        })
        .take(6)
        .collect::<Vec<_>>();
    assert_eq!(historical.len(), 6);
    for id in &historical {
        let raw = actor.carriage_frame(*id).unwrap().retained_bytes().unwrap();
        Node::open(&transport)
            .unwrap()
            .enqueue(&raw, &peers[0])
            .unwrap();
    }
    let head = f.node.storage_head().unwrap();
    actor.broadcast(&transport).unwrap();
    let frame = actor.carriage_frame(prepare).unwrap().message_id;
    let exchange = Node::open(&transport).unwrap().prepare(&peers[0]).unwrap();
    let transits = exchange["body"]["transits"].as_array().unwrap();
    assert_eq!(transits.len(), 4);
    assert!(
        transits
            .iter()
            .any(|t| t["routing"]["body"]["frame_id"] == frame.to_hex()),
        "current Native prepare displaced by unstarted historical packets"
    );
    assert!(
        transits
            .iter()
            .take(2)
            .any(|t| t["routing"]["body"]["frame_id"] == frame.to_hex()),
        "current Native prepare relies on the rotating historical spare instead of first carriage"
    );
    let historical_frames = historical
        .iter()
        .map(|id| actor.carriage_frame(*id).unwrap().message_id.to_hex())
        .collect::<Vec<_>>();
    assert!(
        transits
            .iter()
            .filter(|t| historical_frames.contains(
                &t["routing"]["body"]["frame_id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            ))
            .count()
            >= 2
    );
    for t in transits {
        let raw = STANDARD
            .decode(t["packet"]["body"]["frame"].as_str().unwrap())
            .unwrap();
        let (_, payload) = crate::contact_frame::inspect_bytes(
            &raw,
            None,
            None,
            crate::contact::MAX_PAYLOAD,
            crate::contact::MAX_FRAME,
        )
        .unwrap();
        crate::bft_client::decode::<net::WireEnvelope>(&payload)
            .unwrap()
            .expand()
            .unwrap()
            .verify(&f.node)
            .unwrap();
    }
    assert_eq!(f.node.storage_head().unwrap(), head);
    let root = f.root.clone();
    drop(f.actors);
    drop(f.node);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn latest_signed_round_control_precedes_prior_round_proposal_and_votes() {
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh round-carriage fixture: {}", f.root.display());
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..3 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let context = consensus::Context::current(&f.node).unwrap();
    let keys = f.seeds.iter().copied().map(public).collect::<Vec<_>>();
    let old_leader = keys
        .iter()
        .position(|key| *key == consensus::leader(&context, 0, &keys).unwrap())
        .unwrap();
    let candidate = f.candidate().unwrap();
    let consensus::Message::Proposal(old) = f
        .sign(
            old_leader,
            consensus::Request::Propose {
                round: 0,
                timeout: None,
                snapshot: Box::new(candidate.clone()),
            },
        )
        .unwrap()
    else {
        panic!("proposal shape")
    };
    f.sign(old_leader, consensus::Request::Prepare(old))
        .unwrap();
    let mut timeouts = Vec::new();
    for n in 0..4 {
        let consensus::Message::Timeout(vote) = f
            .sign(
                n,
                consensus::Request::Timeout {
                    context: context.clone(),
                    round: 0,
                },
            )
            .unwrap()
        else {
            panic!("timeout shape")
        };
        timeouts.push(*vote);
    }
    let certificate =
        consensus::TimeoutCertificate::combine(timeouts, &f.node.trust, &f.node.evidence).unwrap();
    let new_leader = keys
        .iter()
        .position(|key| *key == consensus::leader(&context, 1, &keys).unwrap())
        .unwrap();
    let consensus::Message::Proposal(new) = f
        .sign(
            new_leader,
            consensus::Request::Propose {
                round: 1,
                timeout: Some(certificate),
                snapshot: Box::new(candidate),
            },
        )
        .unwrap()
    else {
        panic!("proposal shape")
    };
    f.sign(old_leader, consensus::Request::Prepare(new))
        .unwrap();
    let latest = f
        .sign(
            old_leader,
            consensus::Request::Timeout {
                context: context.clone(),
                round: 1,
            },
        )
        .unwrap();
    let latest = hash(&serde_json::to_value(net::Body::Signed(Box::new(latest))).unwrap()).unwrap();
    let actor = &mut f.actors[old_leader];
    let local = actor
        .archive
        .runtime
        .messages
        .iter()
        .filter(|(_, r)| r.local)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let historical = local.iter().position(|id| {
        let body:net::Body=serde_json::from_value(actor.archive.runtime.messages[id].body.clone()).unwrap();
        matches!(body,net::Body::Signed(message) if matches!(&*message,consensus::Message::Timeout(v) if v.round==0))
    }).unwrap();
    actor.archive.runtime.cursor = historical as u64;
    actor.archive.runtime.height = f.node.chain.height();
    actor.slot = Some((context, 2));
    let currency = f.node.trust.currency().unwrap();
    let transport = json!({"format":MESH,"network":currency,"state":f.root.join(format!("transport-{old_leader}")),"contacts":[]});
    let head = f.node.storage_head().unwrap();
    actor.broadcast(&transport).unwrap();
    assert!(actor.last_broadcast.len() <= 4);
    assert!(
        actor.last_broadcast.contains(&latest),
        "latest Native timeout was displaced by old-round controls"
    );
    assert_eq!(f.node.storage_head().unwrap(), head);
    let root = f.root.clone();
    drop(f.actors);
    drop(f.node);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}
