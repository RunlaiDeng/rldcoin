//! PUBLIC NO-VALUE keys/vector only. Fresh private native/caller/transport state
//! is retained locally; data receipts are never native acceptance or value.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_peer::{self, codec, Config, Network, PeerPin},
    fast_session::{Action, Id, Ingress, Outbound, Session},
    kernel::{fast, Hash},
};
use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn raw(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn id(v: &Value, k: &str) -> Hash {
    raw(v, k).try_into().unwrap()
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-block-batch-v1-vectors.json"
    ))
    .unwrap()
}
#[test]
fn independent_public_batch_and_packet_bytes_replay_complete_native_blocks() {
    use ed25519_dalek::SigningKey;
    let v = vector();
    let chain = id(&v, "chain_hex");
    let blocks = v["blocks_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| hex::decode(b.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    let mut manual = b"RLDFBLK1".to_vec();
    manual.extend([0, 1, 0, 1]);
    manual.extend(chain);
    manual.extend(1u64.to_be_bytes());
    manual.extend(2u16.to_be_bytes());
    for b in &blocks {
        manual.extend((b.len() as u32).to_be_bytes());
        manual.extend(b);
    }
    assert_eq!(manual, raw(&v, "batch_hex"));
    assert_eq!(codec::block_batch(chain, 1, &blocks).unwrap(), manual);
    let (first, decoded) = codec::decode_block_batch(&manual, chain).unwrap();
    assert_eq!(first, 1);
    assert_eq!(
        decoded,
        blocks.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    let packet = codec::Packet::decode(&raw(&v, "packet_hex"), chain).unwrap();
    assert_eq!(packet.id, id(&v, "packet_id_hex"));
    assert_eq!(packet.payload, manual);
    assert_eq!(packet.kind, 9);
    let key = SigningKey::from_bytes(&[181; 32]);
    assert_eq!(
        codec::Packet::create(chain, &key, packet.destination, 9, &manual)
            .unwrap()
            .raw,
        packet.raw
    );
    let mut native = fast::Ledger::from_genesis(&raw(&v, "genesis_hex"), chain, 100000).unwrap();
    for b in decoded {
        native
            .execute(b, v["observed_time"].as_str().unwrap().parse().unwrap())
            .unwrap();
    }
    assert_eq!(native.tip().height(), 2);
}
#[test]
fn batch_rejects_changed_version_chain_ordinals_counts_duplicates_and_truncation() {
    let v = vector();
    let chain = id(&v, "chain_hex");
    let original = raw(&v, "batch_hex");
    for index in [0, 8, 10, 12] {
        let mut b = original.clone();
        b[index] ^= 1;
        assert!(codec::decode_block_batch(&b, chain).is_err());
    }
    for count in [0u16, 33] {
        let mut b = original.clone();
        b[52..54].copy_from_slice(&count.to_be_bytes());
        assert!(codec::decode_block_batch(&b, chain).is_err());
    }
    for first in [0, u64::MAX] {
        let mut b = original.clone();
        b[44..52].copy_from_slice(&first.to_be_bytes());
        assert!(codec::decode_block_batch(&b, chain).is_err());
    }
    let one = hex::decode(v["blocks_hex"][0].as_str().unwrap()).unwrap();
    assert!(codec::block_batch(chain, 1, &[one.clone(), one.clone()]).is_err());
    assert!(codec::block_batch(chain, 1, &[]).is_err());
    assert!(codec::block_batch(chain, 1, &vec![one; 33]).is_err());
    for n in [0, 7, 53, 57, original.len() - 1] {
        assert!(codec::decode_block_batch(&original[..n], chain).is_err());
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(codec::decode_block_batch(&trailing, chain).is_err());
    let mut length = original;
    length[54..58].copy_from_slice(&262145u32.to_be_bytes());
    assert!(codec::decode_block_batch(&length, chain).is_err());
    let mut packet = raw(&v, "packet_hex");
    let last = packet.len() - 1;
    packet[last] ^= 1;
    assert!(codec::Packet::decode(&packet, chain).is_err());
}
#[test]
fn exact_packet_byte_bound_does_not_authorize_a_structural_native_block() {
    use ed25519_dalek::SigningKey;
    let v = vector();
    let chain = id(&v, "chain_hex");
    let mut block = hex::decode(v["blocks_hex"][0].as_str().unwrap()).unwrap();
    block.resize(262144 - codec::BATCH_HEADER - 4, 0);
    let frame = codec::block_batch(chain, 1, &[block.clone()]).unwrap();
    assert_eq!(frame.len(), 262144);
    let key = SigningKey::from_bytes(&[181; 32]);
    let peer = SigningKey::from_bytes(&[182; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        codec::Packet::create(chain, &key, peer, 9, &frame)
            .unwrap()
            .raw
            .len(),
        codec::MAX_PACKET
    );
    block.push(0);
    assert!(codec::block_batch(chain, 1, &[block.clone()]).is_err());
    block.resize(262144, 0);
    assert_eq!(
        codec::Packet::create(chain, &key, peer, 1, &block)
            .unwrap()
            .raw
            .len(),
        codec::MAX_PACKET
    );
    assert!(codec::Packet::create(chain, &key, peer, 10, &frame).is_err());
    let mut native = fast::Ledger::from_genesis(&raw(&v, "genesis_hex"), chain, 100000).unwrap();
    assert!(native
        .execute(
            &block,
            v["observed_time"].as_str().unwrap().parse().unwrap()
        )
        .is_err());
    assert_eq!(native.tip().id(), chain);
}
fn directory(chain: Hash) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-fast-carriage-{}-{}",
        std::process::id(),
        hex::encode(chain)
    ));
    fs::create_dir(&p).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    p
}
fn pair(root: &Path, chain: Hash) -> [PathBuf; 2] {
    let roots = [root.join("peer-a"), root.join("peer-b")];
    let infos = roots
        .each_ref()
        .map(|r| fast_peer::provision(r, chain).unwrap());
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    for i in 0..2 {
        let j = 1 - i;
        let c = Config {
            chain: Id(chain),
            identity: Id(id(&infos[i], "identity")),
            listen: listeners[i].local_addr().unwrap(),
            peers: vec![PeerPin {
                key: Id(id(&infos[j], "identity")),
                endpoint: listeners[j].local_addr().unwrap(),
                certificate_sha256: Id(id(&infos[j], "certificate_sha256")),
            }],
        };
        fast_peer::bind_controlled(
            &roots[i],
            &serde_json::to_vec(&c).unwrap(),
            &root.join(format!("peer-{i}.head")),
            now(),
        )
        .unwrap();
    }
    roots
}
#[test]
fn source_holes_restart_and_invalid_native_batch_never_grant_coverage_or_value() {
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain);
    let peers = pair(&root, chain);
    let node = root.join("source");
    let head = root.join("source.head");
    let mut s = Session::create_controlled(&node, &f.genesis, chain, &head, now()).unwrap();
    let mut blocks = vec![];
    let mut at = 0;
    for i in 0u64..40 {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let raw = f.history[at..at + n].to_vec();
        at += n;
        let mut request = [0; 32];
        request[..8].copy_from_slice(&(i + 1).to_be_bytes());
        let a = Action::Native {
            tip: Id(s.tip()),
            block: hex::encode(&raw),
        };
        assert!(s.execute(Id(request), s.head(), a, None, now()).unwrap()["diagnostic"].is_null());
        blocks.push(raw);
    }
    let target = s.tip();
    let observed = now();
    let mut a =
        Network::open_controlled(&peers[0], chain, &root.join("peer-0.head"), observed).unwrap();
    let destination = id(&a.status(), "identity");
    let info: Value =
        serde_json::from_slice(&fs::read(peers[1].join("admission.json")).unwrap()).unwrap();
    let other = id(&info, "identity");
    assert_ne!(destination, other);
    a.queue(other, 1, &blocks[39], observed).unwrap();
    a.queue(
        other,
        9,
        &codec::block_batch(chain, 1000, &[blocks[0].clone()]).unwrap(),
        observed,
    )
    .unwrap();
    let mut bad = blocks[0].clone();
    loop {
        bad[267] = bad[267].wrapping_add(1);
        let mut native = fast::Ledger::from_genesis(&f.genesis, chain, 100000).unwrap();
        if native.execute(&bad, observed).is_err() {
            break;
        }
    }
    a.queue(
        other,
        9,
        &codec::block_batch(chain, 41, &[bad]).unwrap(),
        observed,
    )
    .unwrap();
    let mut outgoing = Outbound::default();
    outgoing.tick(&mut s, &mut a, observed).unwrap();
    assert_eq!(
        outgoing.status()["neighbors"][0]["source_records_covered_through"],
        "0"
    );
    for _ in 0..8 {
        outgoing.tick(&mut s, &mut a, observed + 2).unwrap();
    }
    assert_eq!(
        outgoing.status()["neighbors"][0]["source_records_covered_through"],
        "32"
    );
    let cold_time = observed + 3;
    outgoing.tick(&mut s, &mut a, cold_time).unwrap();
    assert_eq!(
        outgoing.status()["neighbors"][0]["source_records_covered_through"],
        "40"
    );
    let inventory = a.inventory().unwrap();
    assert_eq!(inventory.as_array().unwrap().len(), 5);
    drop(outgoing);
    drop(a);
    drop(s);
    let mut s = Session::open_controlled(&node, &f.genesis, chain, &head, cold_time).unwrap();
    let mut a =
        Network::open_controlled(&peers[0], chain, &root.join("peer-0.head"), cold_time).unwrap();
    let mut outgoing = Outbound::default();
    outgoing.tick(&mut s, &mut a, cold_time).unwrap();
    assert_eq!(
        outgoing.status()["neighbors"][0]["source_records_covered_through"],
        "40"
    );
    assert_eq!(a.inventory().unwrap(), inventory);
    let mut receiver = Session::create_controlled(
        &root.join("receiver"),
        &f.genesis,
        chain,
        &root.join("receiver.head"),
        cold_time,
    )
    .unwrap();
    let mut b =
        Network::open_controlled(&peers[1], chain, &root.join("peer-1.head"), cold_time).unwrap();
    let mut incoming = Ingress::synchronized();
    loop {
        a.tick(cold_time).unwrap();
        b.tick(cold_time).unwrap();
        let _ = incoming.tick(&mut receiver, &mut b, cold_time);
        let acknowledged = a
            .inventory()
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["destination_transport_custody"] == true);
        if receiver.tip() == target
            && !incoming.status()["deferred_packets"]
                .as_array()
                .unwrap()
                .is_empty()
            && acknowledged
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{}",
            json!({"source":a.status(),"receiver":b.status(),"ingress":incoming.status()})
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        receiver.status(receiver.head(), cold_time).unwrap()["height"],
        "40"
    );
    assert_eq!(a.inventory().unwrap().as_array().unwrap().len(), 5);
    assert_eq!(incoming.status()["key_loading"], false);
    let mut return_path = Outbound::default();
    for _ in 0..8 {
        return_path.tick(&mut receiver, &mut b, cold_time).unwrap();
    }
    assert_eq!(
        b.inventory()
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["received"] == false)
            .count(),
        0,
        "already authenticated sender bytes must not be reflected to that sender"
    );
    let mut other = Session::create_controlled(
        &root.join("other-receiver"),
        &f.genesis,
        chain,
        &root.join("other-receiver.head"),
        cold_time,
    )
    .unwrap();
    assert!(incoming
        .tick(&mut other, &mut b, cold_time)
        .unwrap_err()
        .contains("runtime binding"));
    assert_eq!(other.tip(), chain);
    assert!(Instant::now() < deadline);
}

#[test]
fn ordinary_survivor_mines_and_relays_to_a_later_neighbor_after_origin_stops() {
    use rld_survivor_node::fast_session::BackgroundMiner;
    let deadline = Instant::now() + Duration::from_secs(180);
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain);
    let roots = (0..3)
        .map(|i| root.join(format!("mesh-{i}")))
        .collect::<Vec<_>>();
    let info = roots
        .iter()
        .map(|p| fast_peer::provision(p, chain).unwrap())
        .collect::<Vec<_>>();
    let endpoints = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let neighbors = [vec![1usize], vec![0, 2], vec![1]];
    for i in 0..3 {
        let config = Config {
            chain: Id(chain),
            identity: Id(id(&info[i], "identity")),
            listen: endpoints[i].local_addr().unwrap(),
            peers: neighbors[i]
                .iter()
                .map(|&j| PeerPin {
                    key: Id(id(&info[j], "identity")),
                    endpoint: endpoints[j].local_addr().unwrap(),
                    certificate_sha256: Id(id(&info[j], "certificate_sha256")),
                })
                .collect(),
        };
        fast_peer::bind_controlled(
            &roots[i],
            &serde_json::to_vec(&config).unwrap(),
            &root.join(format!("mesh-{i}.head")),
            now(),
        )
        .unwrap();
    }
    drop(endpoints);
    let mut source = Session::create_controlled(
        &root.join("origin"),
        &f.genesis,
        chain,
        &root.join("origin.head"),
        now(),
    )
    .unwrap();
    let mut at = 0;
    for i in 0u64..40 {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let mut request = [0; 32];
        request[..8].copy_from_slice(&(i + 1).to_be_bytes());
        let action = Action::Native {
            tip: Id(source.tip()),
            block: hex::encode(&f.history[at..at + n]),
        };
        at += n;
        assert!(source
            .execute(Id(request), source.head(), action, None, now())
            .unwrap()["diagnostic"]
            .is_null());
    }
    let origin_tip = source.tip();
    let mut a =
        Network::open_controlled(&roots[0], chain, &root.join("mesh-0.head"), now()).unwrap();
    let mut b =
        Network::open_controlled(&roots[1], chain, &root.join("mesh-1.head"), now()).unwrap();
    let mut middle = Session::create_controlled(
        &root.join("middle"),
        &f.genesis,
        chain,
        &root.join("middle.head"),
        now(),
    )
    .unwrap();
    let mut send = Outbound::default();
    let mut receive = Ingress::synchronized();
    while middle.tip() != origin_tip {
        a.tick(now()).unwrap();
        b.tick(now()).unwrap();
        send.tick(&mut source, &mut a, now()).unwrap();
        let _ = receive.tick(&mut middle, &mut b, now());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(a);
    drop(source);
    let head = middle.head();
    let mut miner = BackgroundMiner::start(
        &mut middle,
        head,
        Id(f.miner.verifying_key().to_bytes()),
        now(),
    )
    .unwrap();
    while middle.tip() == origin_tip {
        miner.tick(&mut middle, now()).unwrap();
        assert!(Instant::now() < deadline);
    }
    let target = middle.tip();
    drop(miner);
    assert_eq!(
        middle.status(middle.head(), now()).unwrap()["actors"],
        json!([])
    );
    let mut destination = Session::create_controlled(
        &root.join("destination"),
        &f.genesis,
        chain,
        &root.join("destination.head"),
        now(),
    )
    .unwrap();
    let mut c =
        Network::open_controlled(&roots[2], chain, &root.join("mesh-2.head"), now()).unwrap();
    let mut relay = Outbound::default();
    let mut delivery = Ingress::synchronized();
    while destination.tip() != target {
        b.tick(now()).unwrap();
        c.tick(now()).unwrap();
        relay.tick(&mut middle, &mut b, now()).unwrap();
        let _ = delivery.tick(&mut destination, &mut c, now());
        assert!(
            Instant::now() < deadline,
            "{}",
            json!({"middle":b.status(),"destination":c.status(),"relay":relay.status(),"delivery":delivery.status()})
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        destination.status(destination.head(), now()).unwrap()["height"],
        "41"
    );
    let inventory = b.inventory().unwrap();
    let origin = hex::encode(id(&info[0], "identity"));
    let later = hex::encode(id(&info[2], "identity"));
    assert!(
        inventory
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["received"] == false && r["destination"] == origin)
            .count()
            <= 1,
        "only new survivor work may be queued back to the stopped origin"
    );
    assert!(inventory
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["received"] == false && r["destination"] == later));
    assert!(Instant::now() < deadline);
}

#[test]
fn deferred_future_packet_keeps_other_runnable_native_data_awake() {
    let deadline = Instant::now() + Duration::from_secs(60);
    let f = support::fixture();
    let chain = f.ledger.chain_id();
    let root = directory(chain);
    let peers = pair(&root, chain);
    let observed = now();
    let mut a =
        Network::open_controlled(&peers[0], chain, &root.join("peer-0.head"), observed).unwrap();
    let mut b =
        Network::open_controlled(&peers[1], chain, &root.join("peer-1.head"), observed).unwrap();
    let destination = id(&b.status(), "identity");
    let mut blocks = vec![];
    let mut at = 0;
    for _ in 0..2 {
        let n = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        blocks.push(f.history[at..at + n].to_vec());
        at += n;
    }
    let mut receiver = Session::create_log_controlled(
        &root.join("receiver"),
        &f.genesis,
        chain,
        &root.join("receiver.head"),
        observed,
    )
    .unwrap();
    a.queue(
        destination,
        9,
        &codec::block_batch(chain, 2, &[blocks[1].clone()]).unwrap(),
        observed,
    )
    .unwrap();
    while b.received_ids(9).unwrap().len() != 1 {
        a.tick(observed).unwrap();
        b.tick(observed).unwrap();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut only_future = Ingress::synchronized();
    assert!(only_future
        .tick(&mut receiver, &mut b, observed)
        .unwrap_err()
        .contains("WAITING_FOR_HISTORY"));
    assert!(
        !only_future.work_pending(),
        "all data deferred at this context may idle"
    );
    a.queue(
        destination,
        9,
        &codec::block_batch(chain, 1, &[blocks[0].clone()]).unwrap(),
        observed,
    )
    .unwrap();
    while b.received_ids(9).unwrap().len() != 2 {
        a.tick(observed).unwrap();
        b.tick(observed).unwrap();
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let prior = receiver.head();
    let mut cold_ingress = Ingress::synchronized();
    assert!(cold_ingress
        .tick(&mut receiver, &mut b, observed)
        .unwrap_err()
        .contains("WAITING_FOR_HISTORY"));
    assert_eq!(receiver.head(), prior);
    assert!(
        cold_ingress.work_pending(),
        "the other retained packet has runnable native data"
    );
    cold_ingress.tick(&mut receiver, &mut b, observed).unwrap();
    assert_eq!(receiver.tip(), fast::block_id(&blocks[0]).unwrap());
    cold_ingress.tick(&mut receiver, &mut b, observed).unwrap();
    assert_eq!(receiver.tip(), fast::block_id(&blocks[1]).unwrap());
    cold_ingress.tick(&mut receiver, &mut b, observed).unwrap();
    assert!(
        !cold_ingress.work_pending(),
        "completed immutable data must not spin"
    );
    let clock = observed.to_string();
    assert!(b
        .inventory()
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["queued_at"].as_str() == Some(clock.as_str())));
    assert!(Instant::now() < deadline);
}
