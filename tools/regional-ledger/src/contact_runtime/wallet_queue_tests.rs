//! Public no-value inputs exercise the normal wallet consent and submission APIs.
use super::*;
use crate::wallet_app::{Action, App, Options};

fn options(root: &Path, currency: Hash, head: Option<Hash>, key: Option<PathBuf>) -> Options {
    Options {
        ledger: root.join("recipient"),
        authority: public(1),
        currency,
        wallet: root.join("wallet"),
        heads: root.join("wallet-caller"),
        owner: public(11),
        expected: head,
        key,
        encrypted_key: None,
        passphrase: None,
        backup_dir: None,
        miner: None,
    }
}

#[test]
fn wallet_bft_submission_queues_without_mining_and_releases_no_value_before_certificate() {
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh wallet BFT fixture: {}", f.root.display());
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..3 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let currency = f.node.trust.currency().unwrap();
    let head = f.node.storage_head().unwrap();
    let input = *f
        .node
        .chain
        .ledger
        .coins
        .iter()
        .find(|(_, c)| c.payment.owner == public(11) && c.mature <= 3)
        .unwrap()
        .0;
    let Fixture {
        root,
        source,
        node,
        actors,
        seeds,
        raw,
    } = f;
    drop(node);
    let key = root.join("public-fixture-wallet-key.json");
    crate::keystore::private_create(
        &key,
        &serde_json::to_vec(&json!({"secret_key":hex::encode([11;32])})).unwrap(),
    )
    .unwrap();
    let mut app = App::open(options(&root, currency, None, Some(key))).unwrap();
    app.act(Action::Init {}).unwrap();
    let preview = app
        .act(Action::Prepare {
            request: json!({"inputs":[input],
        "outputs":[{"owner":public(13),"amount":"98"}],"remote":null,"fee":"0",
        "valid_for_blocks":8,"valid_through":null}),
        })
        .unwrap();
    let signed = app
        .act(Action::Sign {
            review_id: serde_json::from_value(preview["review_id"].clone()).unwrap(),
            review_commitment: serde_json::from_value(preview["review_commitment"].clone())
                .unwrap(),
        })
        .unwrap();
    let intent: Hash = serde_json::from_value(signed["intent_id"].clone()).unwrap();
    let saved = app.saved.clone();
    let queued = app.act(Action::Submit { intent }).unwrap();
    assert_eq!(queued["state"], "QUEUED_FOR_CERTIFIED_INCLUSION");
    assert_eq!(queued["included"], false);
    assert_eq!(queued["finalized"], false);
    assert_eq!(app.act(Action::Submit { intent }).unwrap(), queued);
    let status = app.act(Action::Status {}).unwrap();
    assert_eq!(status["local_submission_enabled"], true);
    assert_eq!(status["local_block_producer_enabled"], false);
    assert_eq!(status["wallet"]["reserved_owned_outputs"], "98");
    assert_eq!(status["wallet"]["available"], "0");
    assert!(app.act(Action::Submit { intent: Hash::ZERO }).is_err());
    assert_eq!(app.saved, saved);
    drop(app);
    let node = Store::open_pinned(&root.join("recipient"), &public(1), currency, head).unwrap();
    assert!(node.chain.ledger.coins.contains_key(&input));
    assert_eq!(node.chain.height(), 3);
    assert_eq!(
        fs::read_dir(root.join("recipient/bft-submissions"))
            .unwrap()
            .count(),
        1
    );
    let message: Hash = serde_json::from_value(queued["message_id"].clone()).unwrap();
    let bytes = files::private_read_with_limit(
        &root.join(format!(
            "recipient/bft-submissions/{}.json",
            message.to_hex()
        )),
        crate::contact::MAX_PAYLOAD,
    )
    .unwrap();
    let envelope = crate::bft_client::decode::<net::WireEnvelope>(&bytes)
        .unwrap()
        .expand()
        .unwrap();
    assert_eq!(envelope.verify(&node).unwrap(), message);
    let net::Body::Submission(commands) = envelope.body else {
        panic!("not a typed submission")
    };
    assert_eq!(serde_json::to_value(&commands).unwrap(), signed["commands"]);
    drop(node);
    // Restart with no key can recover the exact retained signature and submit
    // it again; it cannot first-sign or release the original reservation.
    let mut app = App::open(options(&root, currency, saved.head, None)).unwrap();
    assert_eq!(app.saved, saved);
    assert_eq!(
        app.act(Action::Recover { intent }).unwrap()["commands"],
        signed["commands"]
    );
    assert_eq!(app.act(Action::Submit { intent }).unwrap(), queued);
    drop(app);
    let node = Store::open_pinned(&root.join("recipient"), &public(1), currency, head).unwrap();
    let mut f = Fixture {
        root,
        source,
        node,
        actors,
        seeds,
        raw,
    };
    f.actors[0].submissions(&f.node).unwrap();
    let candidate = f.candidate().unwrap();
    assert_eq!(candidate.blocks.last().unwrap().commands, commands);
    assert!(f.node.chain.ledger.coins.contains_key(&input));
    f.finalize(candidate).unwrap();
    assert!(!f.node.chain.ledger.coins.contains_key(&input));
    assert!(f
        .node
        .chain
        .ledger
        .coins
        .values()
        .any(|c| c.payment.owner == public(13) && c.payment.amount == Amount(98)));
    let after = f.node.storage_head().unwrap();
    let root = f.root.clone();
    drop(f.actors);
    drop(f.node);
    let cold = Store::open_pinned(&root.join("recipient"), &public(1), currency, after).unwrap();
    let client = crate::wallet_client::Client::lock(
        &root.join("wallet-caller"),
        &root.join("wallet"),
        public(11),
        &cold,
    )
    .unwrap();
    assert_eq!(client.read().unwrap(), saved);
    let agent = crate::wallet_agent::Agent::open(&root.join("wallet"), &cold).unwrap();
    let view = agent.view(&cold, saved.head.unwrap()).unwrap();
    assert_eq!(view.reserved_owned_outputs, Amount::ZERO);
    assert_eq!(view.signed[0].state, "INCLUDED_IN_LOCAL_LEDGER");
    assert_eq!(agent.journal.records.len(), 1);
    let third = crate::Chain::new(cold.trust.named("andromeda").unwrap(), &cold.trust).unwrap();
    crate::conservation(&[f.source.chain.clone(), cold.chain.clone(), third]).unwrap();
    drop(agent);
    drop(client);
    drop(cold);
    drop(f.source);
    fs::remove_dir_all(root).unwrap();
}
