//! Bounded work observations use fresh public no-value Native evidence only.
use super::*;
use crate::contact_runtime::service;

#[test]
fn ordinary_contact_work_separates_transport_and_native_verification() {
    let started = service::monotonic().unwrap();
    let deadline = started + 30.0;
    let mut f = Fixture::new().unwrap();
    eprintln!("Fresh ordinary work fixture: {}", f.root.display());
    f.node.contact_apply(&f.raw, None).unwrap();
    for _ in 0..5 {
        let candidate = f.candidate().unwrap();
        f.finalize(candidate).unwrap();
    }
    let mut frames = Vec::new();
    for actor in &f.actors {
        for (id, record) in &actor.archive.runtime.messages {
            if record.local {
                frames.push(actor.carriage_frame(*id).unwrap().retained_bytes().unwrap());
            }
        }
    }
    assert_eq!(frames.len(), 35);
    let currency = f.node.trust.currency().unwrap();
    let ids = f.actors[0]
        .config
        .validators
        .iter()
        .map(|v| v.node_id.clone())
        .collect::<Vec<_>>();
    let contacts = [0usize, 1].map(|n| {
        json!({"peer":ids[1-n],
        "inbox":f.root.join(format!("work-spool-{}-{n}",1-n)),
        "outbox":f.root.join(format!("work-spool-{n}-{}",1-n))})
    });
    let transports = [0usize, 1].map(|n| {
        json!({"format":MESH,"network":currency,
        "state":f.root.join(format!("transport-{n}")),"contacts":[contacts[n].clone()]})
    });
    {
        let mut node = Node::open(&transports[0]).unwrap();
        for raw in &frames {
            node.enqueue(raw, &ids[1]).unwrap();
        }
    }
    let ledger = f.node.directory().to_path_buf();
    let coins = f.node.chain.ledger.coins.clone();
    let heads = (0..4)
        .map(|n| fs::read(f.root.join(format!("caller-{n}/head.json"))).unwrap())
        .collect::<Vec<_>>();
    drop(f.node);
    let mut runtime = Some(f.actors.remove(1));
    runtime.as_mut().unwrap().config.stop_height = 5;
    let options = service::Options {
        ledger: ledger.clone(),
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
    service::start_work_trace();
    let result = (|| -> Result<()> {
        for _ in 0..12 {
            service::spool(&transports[0], &ids[1], &contacts[0])?;
            service::spool(&transports[1], &ids[0], &contacts[1])?;
            service::tick_ledger(
                &options,
                &transports[1],
                &mut runtime,
                &mut cursor,
                &mut seen,
            )?;
            require(
                service::monotonic()? < deadline,
                "ordinary work discriminator original deadline exhausted",
            )?;
        }
        let node = Store::open_inspection(&ledger, &public(1), currency)?;
        require(
            node.chain.height() == 5 && node.chain.ledger.coins == coins,
            "work observation changed Native value",
        )?;
        for (n, head) in heads.iter().enumerate() {
            require(
                fs::read(f.root.join(format!("caller-{n}/head.json")))
                    .map_err(|e| e.to_string())?
                    == *head,
                "work observation changed signing caller head",
            )?;
        }
        require(
            service::monotonic()? < deadline,
            "ordinary work cold closure original deadline exhausted",
        )?;
        Ok(())
    })();
    let trace = service::take_work_trace();
    let mut totals = BTreeMap::<String, (usize, f64)>::new();
    for event in &trace {
        if let Some(seconds) = event["seconds"].as_f64() {
            let value = totals
                .entry(event["phase"].as_str().unwrap().into())
                .or_default();
            value.0 += event["calls"].as_u64().unwrap_or(1) as usize;
            value.1 += seconds;
        }
    }
    atomic(
        &f.root.join("work-observations.json"),
        &json!({"trace":trace,"totals":totals,
        "error":result.as_ref().err(),"whole_seconds":service::monotonic().unwrap()-started,
        "fixture_only":true,"independent_operations":false,"latency_percentiles_qualified":false}),
        4 * 1024 * 1024,
    )
    .unwrap();
    eprintln!("Ordinary work observation totals: {}", json!(totals));
    result.unwrap();
}
