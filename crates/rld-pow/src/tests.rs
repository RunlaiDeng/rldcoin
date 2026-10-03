use super::*;
use rld_core::{generate_identity, sign_bytes};
fn context() -> Context {
    Context {
        network_domain: "fixture:rld-pow".into(),
        zone_id: "fixture-earth".into(),
        currency_genesis: Hash([1; 32]),
        manifest_pin: Hash([2; 32]),
        transition_id: Hash([3; 32]),
        legacy_height: 20,
        legacy_state_root: Hash([4; 32]),
        started_at: 1_000_000,
        initial_target: target_limit(),
    }
}
fn block(chain: &Chain, miner: &str, time: u64, txs: Vec<Transfer>) -> Block {
    let mut b = chain.template(miner.into(), time, txs).unwrap();
    while !mine_batch(&mut b, 100_000).unwrap() {}
    b
}
#[test]
fn streamed_state_root_matches_original_buffered_encoding() {
    fn original(state: &State) -> Result<Hash> {
        let mut bytes = b"RLD-EARTH-POW-UTXO\0".to_vec();
        bytes.extend(state.emitted.0.to_be_bytes());
        let mut total = Amount::ZERO;
        let mut owner_bytes = BTreeMap::new();
        for (point, coin) in &state.coins {
            total = total
                .checked_add(coin.output.amount)
                .map_err(|e| e.to_string())?;
            bytes.extend(point.transaction.0);
            bytes.extend(point.index.to_be_bytes());
            let key = match owner_bytes.get(&coin.output.owner) {
                Some(key) => *key,
                None => {
                    let key = key_bytes(&coin.output.owner)?;
                    owner_bytes.insert(coin.output.owner.clone(), key);
                    key
                }
            };
            bytes.extend(key);
            bytes.extend(coin.output.amount.0.to_be_bytes());
            bytes.extend(coin.spendable_height.to_be_bytes());
        }
        check(
            total == state.emitted && total.0 <= TOTAL_SUPPLY_RUNLAI,
            "supply conservation failed",
        )?;
        Ok(hash(&bytes))
    }
    let owners = [
        generate_identity().public_key,
        generate_identity().public_key,
    ];
    let mut state = State::default();
    assert_eq!(state.root().unwrap(), original(&state).unwrap());
    for index in 0..2_048u32 {
        let amount = Amount(u128::from(index) + 1);
        state.emitted = state.emitted.checked_add(amount).unwrap();
        state.coins.insert(
            OutPoint {
                transaction: hash(&index.to_be_bytes()),
                index: (index % 31) as u16,
            },
            Coin {
                output: Output {
                    owner: owners[(index % 2) as usize].clone(),
                    amount,
                },
                spendable_height: 20 + u128::from(index % 100),
            },
        );
        if index % 128 == 127 {
            assert_eq!(state.root().unwrap(), original(&state).unwrap());
        }
    }
    state.emitted = Amount(state.emitted.0 + 1);
    assert!(state.root().is_err());
    assert!(original(&state).is_err());
}
#[test]
fn emission_is_exact_capped_and_not_a_genesis_allocation() {
    assert_eq!(cumulative_emission(0), 0);
    assert_eq!(
        subsidy(1).unwrap(),
        Amount::from_rld_whole(250_000).unwrap()
    );
    assert_eq!(cumulative_emission(HALVING_BLOCKS), TOTAL_SUPPLY_RUNLAI / 2);
    let mut previous = 0;
    for era in 0..130 {
        let n = era * HALVING_BLOCKS;
        let emitted = cumulative_emission(n);
        assert!(emitted >= previous && emitted <= TOTAL_SUPPLY_RUNLAI);
        previous = emitted;
        for i in [1, HALVING_BLOCKS - 1, HALVING_BLOCKS] {
            let reward = subsidy(n + i).unwrap().0;
            assert_eq!(
                cumulative_emission(n + i) - cumulative_emission(n + i - 1),
                reward
            );
        }
    }
    assert_eq!(cumulative_emission(u128::MAX), TOTAL_SUPPLY_RUNLAI);
    assert!(subsidy(0).is_err());
}
#[test]
fn actual_work_credits_miner_and_rejects_tampering_atomically() {
    let owner = generate_identity();
    let mut chain = Chain::new(context()).unwrap();
    let b = block(&chain, &owner.public_key, 1_000_600, vec![]);
    let initial = chain.tip();
    for mutation in 0..5 {
        let mut bad = b.clone();
        match mutation {
            0 => bad.header.state_root = Hash([9; 32]),
            1 => bad.header.target = Work::MAX,
            2 => bad.header.chain_id = Hash([8; 32]),
            3 => bad.header.height += 1,
            _ => bad.header.timestamp = 1_000_000,
        }
        assert!(chain.accept(bad, 1_000_600).is_err());
        assert_eq!(chain.tip(), initial);
        assert_eq!(chain.state().emitted, Amount::ZERO);
    }
    assert!(chain.accept(b.clone(), 1_000_600).unwrap());
    assert!(!chain.accept(b, 1_000_600).unwrap());
    assert_eq!(
        chain.state().balance(&owner.public_key, chain.height() + 1),
        (Amount::ZERO, subsidy(1).unwrap())
    );
}
#[test]
fn heavier_fork_replaces_orphan_rewards_instead_of_adding_them() {
    let alice = generate_identity();
    let bob = generate_identity();
    let mut a = Chain::new(context()).unwrap();
    let mut b = a.clone();
    let first = block(&a, &alice.public_key, 1_000_600, vec![]);
    a.accept(first, 1_000_600).unwrap();
    let rival = block(&b, &bob.public_key, 1_000_601, vec![]);
    b.accept(rival.clone(), 1_000_601).unwrap();
    assert!(!a.accept(rival, 1_000_601).unwrap()); // Equal work keeps the current tip.
    let next = block(&b, &bob.public_key, 1_001_200, vec![]);
    assert!(a.accept(next, 1_001_200).unwrap());
    assert_eq!(
        a.state().balance(&alice.public_key, a.height() + 1),
        (Amount::ZERO, Amount::ZERO)
    );
    assert_eq!(a.state().emitted, Amount(cumulative_emission(2)));
}
#[test]
fn replay_anchor_follows_best_branch_and_rejects_changed_context() {
    let alice = generate_identity();
    let bob = generate_identity();
    let mut preferred = Chain::new(context()).unwrap();
    assert!(preferred.replay_anchor().is_err());
    let first = block(&preferred, &alice.public_key, 1_000_600, vec![]);
    preferred.accept(first, 1_000_600).unwrap();
    let old_tip = preferred.replay_anchor().unwrap().tip();
    let mut rival = Chain::new(context()).unwrap();
    for time in [1_000_601, 1_001_201] {
        let next = block(&rival, &bob.public_key, time, vec![]);
        rival.accept(next.clone(), time).unwrap();
        preferred.accept(next, time).unwrap();
    }
    let anchor = preferred.replay_anchor().unwrap();
    assert_ne!(anchor.tip(), old_tip);
    assert_eq!(anchor.tip(), rival.tip());
    assert_eq!(anchor.state_root(), rival.state().root().unwrap());
    assert_eq!(
        anchor
            .state()
            .balance(&alice.public_key, anchor.height() + 1),
        (Amount::ZERO, Amount::ZERO)
    );
    preferred.context.zone_id.push_str("-altered");
    assert!(preferred.replay_anchor().is_err());
}
#[test]
fn maturity_signatures_double_spend_and_fee_conservation() {
    let owner = generate_identity();
    let recipient = generate_identity();
    let mut chain = Chain::new(context()).unwrap();
    let b = block(&chain, &owner.public_key, 1_000_600, vec![]);
    chain.accept(b, 1_000_600).unwrap();
    let (outpoint, coin) = chain.state().coins.iter().next().unwrap();
    let mut tx = Transfer {
        chain_id: chain.context.chain_id().unwrap(),
        owner: owner.public_key.clone(),
        inputs: vec![outpoint.clone()],
        outputs: vec![Output {
            owner: recipient.public_key.clone(),
            amount: Amount(coin.output.amount.0 - 1),
        }],
        fee: Amount(1),
        valid_through_height: 1000,
        signature: String::new(),
    };
    tx.signature = sign_bytes(&owner.secret_key, &tx.signing_bytes().unwrap()).unwrap();
    assert!(chain
        .template(owner.public_key.clone(), 1_001_200, vec![tx.clone()])
        .is_err());
    for i in 2..=100 {
        let now = 1_000_000 + i * 600;
        let b = block(&chain, &owner.public_key, now, vec![]);
        chain.accept(b, now).unwrap();
    }
    let mut wrong = tx.clone();
    wrong.signature = "00".repeat(64);
    assert!(chain
        .template(owner.public_key.clone(), 1_060_600, vec![wrong])
        .is_err());
    assert!(chain
        .template(
            owner.public_key.clone(),
            1_060_600,
            vec![tx.clone(), tx.clone()]
        )
        .is_err());
    let b = block(&chain, &owner.public_key, 1_060_600, vec![tx.clone()]);
    chain.accept(b, 1_060_600).unwrap();
    assert_eq!(
        chain
            .state()
            .balance(&recipient.public_key, chain.height() + 1)
            .0,
        tx.outputs[0].amount
    );
    assert!(chain
        .template(owner.public_key.clone(), 1_061_200, vec![tx])
        .is_err());
    chain.state().root().unwrap();
}
#[test]
fn wrong_network_and_noncanonical_input_are_rejected() {
    let owner = generate_identity();
    let chain = Chain::new(context()).unwrap();
    let b = block(&chain, &owner.public_key, 1_000_600, vec![]);
    let mut raw = serde_json::to_value(&b).unwrap();
    raw["header"]["height"] = serde_json::json!(21);
    assert!(serde_json::from_value::<Block>(raw.clone()).is_err());
    raw["header"]["height"] = serde_json::json!("021");
    assert!(serde_json::from_value::<Block>(raw).is_err());
    let mut other = context();
    other.zone_id = "fixture-mars".into();
    assert!(Chain::new(other).unwrap().accept(b, 1_000_600).is_err());
}
#[test]
fn wide_retarget_does_not_wrap_and_enforces_bounds() {
    assert_eq!(scale_target(target_limit(), 4, 1).unwrap(), target_limit());
    assert_eq!(
        scale_target(Work([100, 0, 0, 0]), 1, 4).unwrap(),
        Work([25, 0, 0, 0])
    );
    assert_eq!(
        scale_target(Work([1, 0, 0, 0]), 1, 4).unwrap(),
        Work([1, 0, 0, 0])
    );
    assert!(scale_target(target_limit(), 1, 0).is_err());
}

fn temp_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "rld-pow-{}-{}",
        std::process::id(),
        generate_identity().public_key
    ));
    std::fs::create_dir(&p).unwrap();
    p
}
#[test]
fn durable_restart_replays_reward_and_exclusive_owner() {
    let dir = temp_dir();
    let miner = generate_identity();
    let tip;
    {
        let mut store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        assert!(storage::Store::open(&dir, context(), 2_000_000).is_err());
        let b = block(store.chain(), &miner.public_key, 1_000_600, vec![]);
        tip = b.header.id().unwrap();
        store.accept(b, 1_000_600).unwrap();
    }
    {
        let store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        assert_eq!(store.chain().tip(), tip);
        assert_eq!(store.chain().state().emitted, subsidy(1).unwrap());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn incomplete_temp_is_unpublished_but_corrupt_committed_block_halts_recovery() {
    let dir = temp_dir();
    let miner = generate_identity();
    let tip;
    {
        let mut store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        let b = block(store.chain(), &miner.public_key, 1_000_600, vec![]);
        tip = b.header.id().unwrap();
        store.accept(b, 1_000_600).unwrap();
    }
    std::fs::write(dir.join("blocks/crash.pending"), b"{incomplete").unwrap();
    {
        let store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        assert_eq!(store.chain().tip(), tip);
    }
    std::fs::write(
        dir.join("blocks").join(format!("{}.json", tip.to_hex())),
        b"{incomplete",
    )
    .unwrap();
    assert!(storage::Store::open(&dir, context(), 2_000_000).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn failed_disk_publication_never_exposes_reward_and_requires_replay() {
    let dir = temp_dir();
    let miner = generate_identity();
    {
        let mut store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        let b = block(store.chain(), &miner.public_key, 1_000_600, vec![]);
        std::fs::remove_dir(dir.join("blocks")).unwrap();
        std::fs::write(dir.join("blocks"), b"fault").unwrap();
        assert!(store.accept(b, 1_000_600).is_err());
        assert_eq!(store.chain().state().emitted, Amount::ZERO);
        assert!(!store.healthy());
    }
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn equal_work_tip_choice_survives_restart() {
    let dir = temp_dir();
    let alice = generate_identity();
    let bob = generate_identity();
    let a = Chain::new(context()).unwrap();
    let first = block(&a, &alice.public_key, 1_000_600, vec![]);
    let second = block(&a, &bob.public_key, 1_000_601, vec![]);
    let tip = first.header.id().unwrap();
    {
        let mut store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        store.accept(first, 1_000_600).unwrap();
        store.accept(second, 1_000_601).unwrap();
        assert_eq!(store.chain().tip(), tip);
    }
    {
        let store = storage::Store::open(&dir, context(), 2_000_000).unwrap();
        assert_eq!(store.chain().tip(), tip);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rule_adoption_requires_pinned_history_all_validators_and_zero_allocation() {
    use ed25519_dalek::SigningKey;
    use transition::*;
    let genesis = include_bytes!("../../../vectors/m0-genesis-v3/manifest.json");
    let history = b"[]";
    let manifest = rld_core::M0GenesisManifestFile::decode_json(genesis).unwrap();
    let pin = Hash::from_hex(manifest.manifest_sha256()).unwrap();
    let d = manifest.descriptor();
    let mut s = AdoptionStatement {
        format: FORMAT.into(),
        manifest_pin: pin,
        network_domain: d.network_domain.clone(),
        zone_id: d.zone_id.clone(),
        currency_genesis: Hash::from_hex(&d.currency_genesis_root).unwrap(),
        legacy_height: 0,
        legacy_state_root: Hash::from_hex(manifest.genesis_state_root()).unwrap(),
        legacy_history_sha256: hash(history),
        rules_sha256: rules_hash(),
        implementation_source_sha256: Hash::from_hex(
            rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
        )
        .unwrap(),
        started_at: 1_000_000,
        initial_target: target_limit(),
        old_service_reserves_reassigned: Amount::TOTAL_SUPPLY,
        personal_allocation: Amount::ZERO,
        incompatible_with_m0_constitution: true,
    };
    let signed = |s: &AdoptionStatement| {
        let mut approvals = Vec::new();
        for seed in 2..=5 {
            let secret = hex::encode([seed; 32]);
            let key = SigningKey::from_bytes(&[seed; 32]);
            approvals.push(Approval {
                public_key: hex::encode(key.verifying_key().to_bytes()),
                signature: sign_bytes(&secret, &s.signing_bytes().unwrap()).unwrap(),
            });
        }
        approvals.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        Adoption {
            statement: s.clone(),
            approvals,
        }
    };
    let valid = signed(&s);
    let context = valid
        .verify(genesis, history, pin, s.id().unwrap())
        .unwrap();
    assert_eq!(context.zone_id, d.zone_id);
    let mut missing = valid.clone();
    missing.approvals.pop();
    assert!(missing
        .verify(genesis, history, pin, s.id().unwrap())
        .is_err());
    let mut duplicate = valid.clone();
    duplicate.approvals[1] = duplicate.approvals[0].clone();
    assert!(duplicate
        .verify(genesis, history, pin, s.id().unwrap())
        .is_err());
    assert!(valid.verify(genesis, b"[ ]", pin, s.id().unwrap()).is_err());
    assert!(valid.verify(genesis, history, pin, Hash([8; 32])).is_err());
    s.personal_allocation = Amount(1);
    assert!(signed(&s)
        .verify(genesis, history, pin, s.id().unwrap())
        .is_err());
    s.personal_allocation = Amount::ZERO;
    s.incompatible_with_m0_constitution = false;
    assert!(signed(&s)
        .verify(genesis, history, pin, s.id().unwrap())
        .is_err());
}

#[test]
fn valid_shorter_harder_branch_wins_and_reorg_recomputes_emission() {
    let alice = generate_identity();
    let bob = generate_identity();
    let mut local = Chain::new(context()).unwrap();
    let mut harder = local.clone();
    for i in 1..=154 {
        let t = 1_000_000 + i * 600;
        let b = block(&local, &alice.public_key, t, vec![]);
        local.accept(b, 2_000_000).unwrap();
    }
    for i in 1..=148 {
        let t = 1_000_000 + i * 120;
        let b = block(&harder, &bob.public_key, t, vec![]);
        if i == 145 {
            assert_eq!(b.header.target, scale_target(target_limit(), 1, 4).unwrap());
        }
        harder.accept(b.clone(), 2_000_000).unwrap();
        local.accept(b, 2_000_000).unwrap();
    }
    assert_eq!(local.tip(), harder.tip());
    assert_eq!(local.height(), context().legacy_height + 148);
    assert_eq!(local.state().emitted, Amount(cumulative_emission(148)));
    assert_eq!(
        local.state().balance(&alice.public_key, local.height() + 1),
        (Amount::ZERO, Amount::ZERO)
    );
}

#[test]
fn bounded_header_window_matches_full_history_across_two_retargets() {
    let owner = generate_identity();
    let mut chain = Chain::new(context()).unwrap();
    let mut timestamp = 1_000_000u64;
    for sequence in 1..=290u64 {
        timestamp += if sequence <= 144 { 600 } else { 300 };
        let mined = block(&chain, &owner.public_key, timestamp, vec![]);
        chain.accept(mined, 2_000_000).unwrap();

        let next_time = timestamp + 600;
        let actual = chain
            .next_header(chain.tip(), owner.public_key.clone(), next_time, &[])
            .unwrap();
        let full = chain.ancestry(chain.tip()).unwrap();
        let mut times: Vec<_> = full
            .iter()
            .rev()
            .take(11)
            .map(|block| block.header.timestamp)
            .collect();
        if times.len() < 11 {
            times.push(chain.context.started_at);
        }
        times.sort_unstable();
        assert!(next_time > times[times.len() / 2]);
        let mut expected_target = full.last().unwrap().header.target;
        if full.len().is_multiple_of(RETARGET_BLOCKS) {
            let end = full.last().unwrap().header.timestamp;
            let begin = full[full.len() - RETARGET_BLOCKS].header.timestamp;
            let expected_span = (RETARGET_BLOCKS as u64 - 1) * BLOCK_SECONDS;
            let elapsed = end
                .saturating_sub(begin)
                .clamp(expected_span / 4, expected_span * 4);
            expected_target = scale_target(expected_target, elapsed, expected_span).unwrap();
        }
        assert_eq!(
            actual.height,
            chain.context.legacy_height + sequence as u128 + 1
        );
        assert_eq!(actual.parent, chain.tip());
        assert_eq!(actual.target, expected_target, "sequence {sequence}");
    }
}

#[test]
fn independent_python_vectors_match_wide_heights_work_hashes_and_emission() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/earth-pow/vectors.json")).unwrap();
    for c in v["emission"].as_array().unwrap() {
        let n: u128 = c["blocks"].as_str().unwrap().parse().unwrap();
        assert_eq!(cumulative_emission(n).to_string(), c["cumulative_runlai"]);
    }
    for c in v["work"].as_array().unwrap() {
        let target = Work::from_hex(c["target"].as_str().unwrap()).unwrap();
        assert_eq!(rld_core::header_work(target).to_hex(), c["work"]);
    }
    let header: Header = serde_json::from_value(v["header"]["value"].clone()).unwrap();
    assert_eq!(
        hex::encode(header.canonical_bytes().unwrap()),
        v["header"]["canonical_hex"]
    );
    assert_eq!(header.id().unwrap().to_hex(), v["header"]["block_id"]);
}

#[test]
fn template_clock_handles_future_median_without_relaxing_validation() {
    let owner = generate_identity();
    let mut chain = Chain::new(context()).unwrap();
    assert_eq!(chain.template_time(1_000_000).unwrap(), 1_000_001);
    let b = block(&chain, &owner.public_key, 1_002_000, vec![]);
    chain.accept(b, 1_000_000).unwrap();
    let time = chain.template_time(1_000_000).unwrap();
    assert_eq!(time, 1_002_001);
    let b = block(&chain, &owner.public_key, time, vec![]);
    chain.accept(b, 1_000_000).unwrap();
    assert!(chain.template(owner.public_key, 1_000_000, vec![]).is_err());
}
