use super::transcript::{ReplayAdmissionSource, ReplayEvent, ReplayFrame};
use super::*;
use crate::*;

const GENESIS: &[u8] = include_bytes!("../../../../vectors/m0-genesis-v3/manifest.json");
const PIN: &str = "a8bb9ebc1d3246725325ce93974b0efde21d76ee1494091978314b46e7014118";

#[test]
fn historical_upgrade_activation_replays_old_signatures_without_live_build_permission() {
    let bytes =
        include_bytes!("../../../../vectors/upgrade-history-v1/activation-1c944737/history.jsonl");
    assert_eq!(
        hash_bytes(bytes),
        "1dee1949d9a657d413bdff137ad3cf7d5e4c9d57cc64e6c2a3725cdaad5e99c9"
    );
    let commits: Vec<_> = bytes
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let frame = ReplayFrame::decode_line(line).unwrap();
            let ReplayEvent::CertifiedCommit(commit) = frame.event else {
                panic!("expected old certificate")
            };
            commit
        })
        .collect();
    assert_eq!(commits.len(), 130);
    let genesis_replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    genesis_replay
        .check_signed_proposal(&commits[0].proposal)
        .unwrap();
    assert!(genesis_replay
        .check_signed_proposal_for_local_authorization(&commits[0].proposal)
        .is_err());
    let mut unsigned = commits[0].proposal.clone();
    unsigned.signature.clear();
    genesis_replay.check_unsigned_proposal(&unsigned).unwrap();
    assert!(genesis_replay
        .check_unsigned_proposal_for_local_authorization(&unsigned)
        .is_err());
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for commit in &commits[..128] {
        replay.replay_candidate_commit(commit).unwrap();
    }
    // Historical acceptance never proves this installed build may sign anew.
    replay
        .check_signed_proposal(&commits[128].proposal)
        .unwrap();
    assert!(replay
        .check_signed_proposal_for_local_authorization(&commits[128].proposal)
        .is_err());
    let mut unsigned = commits[128].proposal.clone();
    unsigned.signature.clear();
    replay.check_unsigned_proposal(&unsigned).unwrap();
    assert!(replay
        .check_unsigned_proposal_for_local_authorization(&unsigned)
        .is_err());
    let before = serde_json::to_vec(replay.ledger()).unwrap();
    let ConsensusCommand::ActivateUpgrade(activation) = &commits[128].proposal.command else {
        panic!("expected activation")
    };
    assert!(replay
        .ledger()
        .inspect_upgrade_activation_for_current_build(activation)
        .unwrap_err()
        .contains("installed implementation source"));
    assert!(replay
        .ledger()
        .preview_first_upgrade_activation(activation)
        .is_err());
    let mut weak = commits[128].as_ref().clone();
    weak.votes.truncate(1);
    assert!(replay.replay_candidate_commit(&weak).is_err());
    for wrong_intent in [false, true] {
        let mut proposal = commits[128].proposal.clone();
        if wrong_intent {
            let ConsensusCommand::ActivateUpgrade(activation) = &mut proposal.command else {
                unreachable!()
            };
            activation.intent_id = AdmissionHash32([9; 32]);
            proposal.command_hash = proposal
                .command
                .wire_v1_command_hash("rldcoin:mainnet:v1")
                .unwrap();
        } else {
            proposal.expected_state_root = "09".repeat(32);
        }
        resign(&mut proposal);
        assert!(replay
            .replay_candidate_commit(&certificate(proposal))
            .is_err());
        assert_eq!(serde_json::to_vec(replay.ledger()).unwrap(), before);
    }
    for commit in &commits[128..] {
        replay.replay_candidate_commit(commit).unwrap();
    }
    assert_eq!(replay.ledger().height, 130);
    assert_eq!(
        replay.ledger().state_root().unwrap(),
        "6355d864e667688495f872158dc57af904c68bd9e76ce515d99296b6d405c24a"
    );
    assert!(replay.ledger().m0_pending_upgrade.is_none());
    assert_eq!(
        replay
            .ledger()
            .m0_active_protocol
            .as_ref()
            .unwrap()
            .upgrade_sequence,
        1
    );
    let after = serde_json::to_vec(replay.ledger()).unwrap();
    replay.replay_candidate_commit(&commits[128]).unwrap();
    assert_eq!(serde_json::to_vec(replay.ledger()).unwrap(), after);
    let manifest: crate::SignedM0GenesisManifestV3 = serde_json::from_slice(GENESIS).unwrap();
    assert!(manifest.validate_ledger_identity(replay.ledger()).is_err());
    let observation = replay.observe_admission().unwrap();
    assert_eq!(observation.report().finalized_height, "130");
    assert_eq!(
        observation.report().finalized_state_root,
        replay.ledger().state_root().unwrap()
    );
    assert!(!observation.report().signature_authorized);
    assert!(!observation.report().live_censorship_policy_active);
    let obligations = replay.admission_obligations(&Default::default()).unwrap();
    assert_eq!(obligations.current_finalized_height, "130");
    assert_eq!(obligations.total_observed_entries, 0);
    assert!(!obligations.signature_authorized);
    assert!(!obligations.recovery_authorized);
    let mut missing_certificate = replay.clone();
    missing_certificate.anchors.remove(&130);
    assert!(missing_certificate.observe_admission().is_err());
    let mut wrong_birth = replay.clone();
    wrong_birth
        .ledger
        .descriptor
        .display_name
        .push_str("-substituted");
    assert!(wrong_birth.observe_admission().is_err());
    assert_eq!(serde_json::to_vec(replay.ledger()).unwrap(), after);
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 130,
        block_id: replay.anchors[&130],
    };
    let mut parent = genesis.genesis_header;
    let mut cumulative = AdmissionWork::ZERO;
    for height in 1..=33 {
        let submitted = source_with_expiry(
            &genesis,
            &anchor,
            parent,
            height,
            cumulative,
            height == 1,
            230,
        );
        parent = submitted.header.header_id();
        cumulative = submitted.header.cumulative_work;
        replay.append_admission_source(&submitted).unwrap();
    }
    let observation = replay.observe_admission().unwrap();
    assert!(observation.report().confirmed_prefix.is_some());
    let obligations = replay.admission_obligations(&Default::default()).unwrap();
    assert_eq!(obligations.total_observed_entries, 1);
    assert_eq!(
        obligations.entries[0].first_confirmed_at_finalized_height,
        "130"
    );
    assert!(!obligations.signature_authorized);
    assert!(!obligations.recovery_authorized);
    assert_eq!(serde_json::to_vec(replay.ledger()).unwrap(), after);
}

#[test]
fn historical_upgrade_schedule_replays_exact_old_certificate_and_rejects_mixed_artifacts() {
    let bytes = include_bytes!("../../../../vectors/upgrade-history-v1/schedule-b8e145ea.jsonl");
    assert_eq!(
        hash_bytes(bytes),
        "e3eea4804fb75133fb45334b3d1417e7efcedbe5534a8274ecd407fb463a4488"
    );
    let frame = ReplayFrame::decode_line(bytes.strip_suffix(b"\n").unwrap()).unwrap();
    let ReplayEvent::CertifiedCommit(commit) = frame.event else {
        panic!("expected certificate")
    };
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let genesis = replay.ledger().clone();
    replay.replay_candidate_commit(&commit).unwrap();
    assert_eq!(replay.ledger().height, 1);
    assert_eq!(
        replay.ledger().state_root().unwrap(),
        "7159a7af3defba8af744c00d103a7512a4518fcf1f8c15be837ed93c90c2fa98"
    );
    let committed = serde_json::to_vec(replay.ledger()).unwrap();
    replay.replay_candidate_commit(&commit).unwrap();
    assert_eq!(serde_json::to_vec(replay.ledger()).unwrap(), committed);
    assert_ne!(
        replay
            .ledger()
            .m0_pending_upgrade
            .as_ref()
            .unwrap()
            .schedule
            .implementation_source_commitment
            .to_hex(),
        crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT
    );
    // Synthetic local boundary for the preflight-only rejection check; this
    // is not presented as certified height-128 historical evidence.
    let mut boundary = replay.ledger().clone();
    let schedule = &boundary.m0_pending_upgrade.as_ref().unwrap().schedule;
    let activation = crate::genesis::upgrade_wire::ActivateUpgradeV1 {
        format_version: "RLD-ACTIVATE-UPGRADE-V1".into(),
        network_domain: schedule.network_domain.clone(),
        zone_id: schedule.zone_id.clone(),
        currency_genesis: schedule.currency_genesis,
        protocol_era: schedule.protocol_era,
        crypto_era: schedule.crypto_era,
        sequence: schedule.sequence,
        activation_height: schedule.activation_height,
        intent_id: AdmissionHash32::from_hex(&schedule.intent_id().unwrap()).unwrap(),
    };
    boundary.height = u64::try_from(activation.activation_height - 1).unwrap();
    let before = serde_json::to_vec(&boundary).unwrap();
    assert!(boundary
        .preview_first_upgrade_activation(&activation)
        .unwrap_err()
        .contains("installed implementation source"));
    assert!(boundary
        .execute_consensus_command(ConsensusCommand::ActivateUpgrade(Box::new(
            activation.clone()
        )))
        .unwrap_err()
        .to_string()
        .contains("not a supported compiled activation tuple"));
    assert_eq!(serde_json::to_vec(&boundary).unwrap(), before);
    for field in 0..8 {
        let mut proposal = commit.proposal.clone();
        let ConsensusCommand::ScheduleUpgrade(schedule) = &mut proposal.command else {
            unreachable!()
        };
        match field {
            0 => schedule.implementation_source_commitment = AdmissionHash32([9; 32]),
            1 => schedule.migration_code_hash = AdmissionHash32([9; 32]),
            2 => schedule.specification_hash = AdmissionHash32([9; 32]),
            3 => schedule.vector_root = AdmissionHash32([9; 32]),
            4 => schedule.migration_id = "UNSUPPORTED_MIGRATION".into(),
            5 => schedule.required_capabilities = vec!["UNSUPPORTED_CAPABILITY".into()],
            6 => {
                schedule.implementation_source_commitment = AdmissionHash32::from_hex(
                    crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
                )
                .unwrap()
            }
            7 => {
                schedule.migration_code_hash = AdmissionHash32::from_hex(
                    &crate::genesis::upgrade_migration::first_migration_descriptor()
                        .migration_code_hash,
                )
                .unwrap()
            }
            _ => unreachable!(),
        }
        proposal.command_hash = proposal
            .command
            .wire_v1_command_hash(&genesis.descriptor.network_domain)
            .unwrap();
        resign(&mut proposal);
        let bad = certificate(proposal);
        let mut rejected = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
        assert!(
            rejected.replay_candidate_commit(&bad).is_err(),
            "field {field}"
        );
        assert_eq!(
            serde_json::to_vec(rejected.ledger()).unwrap(),
            serde_json::to_vec(&genesis).unwrap()
        );
    }
    let mut insufficient = *commit;
    insufficient.votes.truncate(1);
    let mut rejected = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    assert!(rejected.replay_candidate_commit(&insufficient).is_err());
    assert_eq!(rejected.ledger().height, 0);
}

fn identity(seed: u8) -> Identity {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    Identity {
        secret_key: hex::encode(key.to_bytes()),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }
}

fn validators() -> Vec<Identity> {
    (2..=5).map(identity).collect()
}

fn signed_proposal(replay: &M0CandidateReplay, command: ConsensusCommand) -> ConsensusProposal {
    let ledger = replay.ledger();
    let network = &ledger.descriptor.network_domain;
    let (height, root) = match &command {
        ConsensusCommand::CommitAdmissionCheckpoint(proof) => {
            let plan = ledger.plan_admission_checkpoint_proposal(proof).unwrap();
            let transition = replay.verify_checkpoint(proof, &plan).unwrap();
            ledger
                .admission_checkpoint_successor_commitment_from_plan(&plan, &transition)
                .unwrap()
        }
        _ => {
            let mut next = ledger.clone();
            next.execute_consensus_command(command.clone()).unwrap();
            (next.height, next.state_root().unwrap())
        }
    };
    let leader =
        deterministic_round_zero_leader(&ledger.descriptor.validator_keys, ledger.height).unwrap();
    let mut proposal = ConsensusProposal {
        proposal_id: format!("semantic-replay-{height}"),
        zone_id: ledger.descriptor.zone_id.clone(),
        currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
        protocol_era: ledger.descriptor.protocol_era,
        crypto_era: ledger.descriptor.crypto_era,
        parent_height: ledger.height,
        parent_state_root: ledger.state_root().unwrap(),
        round: 0,
        proposer_public_key: leader,
        command_hash: command.wire_v1_command_hash(network).unwrap(),
        command,
        expected_height: height,
        expected_state_root: root,
        signature: String::new(),
    };
    resign(&mut proposal);
    proposal
}

fn resign(proposal: &mut ConsensusProposal) {
    let key = validators()
        .into_iter()
        .find(|v| v.public_key == proposal.proposer_public_key)
        .unwrap();
    proposal.signature = sign_bytes(
        &key.secret_key,
        &proposal
            .wire_v1_signing_bytes("rldcoin:mainnet:v1")
            .unwrap(),
    )
    .unwrap();
}

fn certificate(proposal: ConsensusProposal) -> ConsensusCommit {
    let votes = validators()[..3]
        .iter()
        .map(|v| {
            let mut vote = ConsensusVote {
                proposal_id: proposal.proposal_id.clone(),
                proposal_hash: proposal
                    .wire_v1_proposal_hash("rldcoin:mainnet:v1")
                    .unwrap(),
                zone_id: proposal.zone_id.clone(),
                currency_genesis_root: proposal.currency_genesis_root.clone(),
                protocol_era: proposal.protocol_era,
                crypto_era: proposal.crypto_era,
                parent_height: proposal.parent_height,
                parent_state_root: proposal.parent_state_root.clone(),
                round: 0,
                expected_state_root: proposal.expected_state_root.clone(),
                voter_public_key: v.public_key.clone(),
                signature: String::new(),
            };
            vote.signature = sign_bytes(
                &v.secret_key,
                &vote.wire_v1_signing_bytes("rldcoin:mainnet:v1").unwrap(),
            )
            .unwrap();
            vote
        })
        .collect();
    ConsensusCommit { proposal, votes }
}

fn heartbeat(replay: &M0CandidateReplay) -> ConsensusCommit {
    let ledger = replay.ledger();
    certificate(signed_proposal(
        replay,
        ConsensusCommand::NetworkHeartbeat(NetworkHeartbeatV1 {
            heartbeat_id: format!("semantic-heartbeat-{}", ledger.height),
            zone_id: ledger.descriptor.zone_id.clone(),
            currency_genesis_root: ledger.descriptor.currency_genesis_root.clone(),
            protocol_era: ledger.descriptor.protocol_era,
            crypto_era: ledger.descriptor.crypto_era,
            parent_height: ledger.height,
            note_hash: hash_bytes(b"semantic replay heartbeat"),
        }),
    ))
}

fn same_state(left: &M0CandidateReplay, right: &M0CandidateReplay) {
    assert_eq!(
        serde_json::to_vec(&left.ledger).unwrap(),
        serde_json::to_vec(&right.ledger).unwrap()
    );
    assert_eq!(left.log, right.log);
    assert_eq!(left.anchors, right.anchors);
    assert_eq!(left.admission_inclusions, right.admission_inclusions);
    assert_eq!(left.admission_obligations, right.admission_obligations);
    assert_eq!(left.sidecars, right.sidecars);
    assert_eq!(left.sidecar_bytes, right.sidecar_bytes);
    assert_eq!(left.retained_headers, right.retained_headers);
    assert_eq!(left.retained_entries, right.retained_entries);
    assert_eq!(left.retained_commit_bytes, right.retained_commit_bytes);
}

fn source(
    genesis: &AdmissionGenesisV1,
    anchor: &AdmissionLedgerAnchorV1,
    parent: AdmissionHash32,
    height: u128,
    cumulative: AdmissionWork,
    with_entry: bool,
) -> AdmissionVerifiedHeaderSubmissionV1 {
    source_with_expiry(genesis, anchor, parent, height, cumulative, with_entry, 100)
}

fn source_with_expiry(
    genesis: &AdmissionGenesisV1,
    anchor: &AdmissionLedgerAnchorV1,
    parent: AdmissionHash32,
    height: u128,
    cumulative: AdmissionWork,
    with_entry: bool,
    expiry: u128,
) -> AdmissionVerifiedHeaderSubmissionV1 {
    let mut entries = Vec::new();
    if with_entry {
        let owner = identity(15);
        let payload = format!("independently retained sidecar {height}").into_bytes();
        let commitment = admission_sidecar_payload_commitment(&payload).unwrap();
        let mut entry = PermissionlessAdmissionEntryV1 {
            context: genesis.context.clone(),
            kind: AdmissionEntryKindV1::Participation,
            participant_key: AdmissionHash32::from_hex(&owner.public_key).unwrap(),
            owner_commitment: AdmissionHash32([22; 32]),
            program_id: AdmissionHash32([23; 32]),
            challenge_id: None,
            payload_commitment: commitment,
            locator_commitment: admission_sidecar_locator_commitment(
                commitment,
                payload.len() as u64,
            ),
            declared_bytes: payload.len() as u64,
            expiry_height: expiry,
            entry_signature: AdmissionSignature64([0; 64]),
        };
        entry.entry_signature = AdmissionSignature64(
            hex::decode(sign_bytes(&owner.secret_key, &entry.signing_subject().0).unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        entries.push(AdmissionSidecarSubmissionV1 { entry, payload });
    }
    let entries_root = admission_entry_root(entries.iter().map(|e| e.entry.entry_id())).unwrap();
    let mut work = BaselineAccessWorkV1 {
        context: genesis.context.clone(),
        parent_header: parent,
        ledger_anchor_block: anchor.block_id,
        ledger_anchor_height: anchor.height,
        entries_root,
        entries_count: entries.len() as u16,
        suite_id: ADMISSION_ACCESS_WORK_SUITE_V1,
        target: genesis.config.genesis_target,
        nonce: 0,
        output_hash: AdmissionHash32::ZERO,
        expiry_anchor_height: expiry,
    };
    loop {
        work.output_hash = work.recompute_output_hash();
        if AdmissionWork::from_be_bytes(work.output_hash.0) <= work.target {
            break;
        }
        work.nonce += 1;
    }
    let header = PermissionlessAdmissionHeaderV1 {
        context: genesis.context.clone(),
        admission_era: 0,
        log_height: height,
        parent_header: parent,
        ledger_anchor_block: anchor.block_id,
        access_work_id: work.work_id(),
        entries_root,
        entries_count: entries.len() as u16,
        cumulative_work: cumulative.checked_add(work.header_work()).unwrap(),
        prior_era_terminal: None,
    };
    AdmissionVerifiedHeaderSubmissionV1 {
        entries,
        access_work: work,
        header,
        ledger_anchor: anchor.clone(),
    }
}

#[test]
fn certified_prefix_rejects_fake_roots_quorum_and_history_replacement_atomically() {
    assert!(M0CandidateReplay::from_pinned_genesis(GENESIS, &"0".repeat(64)).is_err());
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let first = heartbeat(&replay);
    let initial = replay.clone();
    let mut deficient = first.clone();
    deficient.votes.pop();
    assert!(replay.replay_candidate_commit(&deficient).is_err());
    same_state(&replay, &initial);
    let mut duplicate = first.clone();
    duplicate.votes[1] = duplicate.votes[0].clone();
    assert!(replay.replay_candidate_commit(&duplicate).is_err());
    same_state(&replay, &initial);
    let mut forged = first.proposal.clone();
    forged.expected_state_root = "44".repeat(32);
    resign(&mut forged);
    let forged = certificate(forged);
    forged
        .verify_wire_v1(
            &replay.ledger.descriptor.validator_keys,
            "rldcoin:mainnet:v1",
        )
        .unwrap();
    assert!(replay.replay_candidate_commit(&forged).is_err());
    same_state(&replay, &initial);
    replay.check_signed_proposal(&first.proposal).unwrap();
    same_state(&replay, &initial);
    replay.replay_candidate_commit(&first).unwrap();
    let once = replay.clone();
    replay.replay_candidate_commit(&first).unwrap();
    same_state(&replay, &once);
    let mut conflict = first.proposal.clone();
    conflict.proposal_id = "another-id".into();
    resign(&mut conflict);
    assert!(replay
        .replay_candidate_commit(&certificate(conflict))
        .is_err());
    same_state(&replay, &once);
    let mut closed = heartbeat(&replay).proposal;
    closed.command = ConsensusCommand::ActivatePendingValueRiskPolicy;
    closed.command_hash = closed
        .command
        .wire_v1_command_hash("rldcoin:mainnet:v1")
        .unwrap();
    resign(&mut closed);
    assert!(replay
        .replay_candidate_commit(&certificate(closed))
        .is_err());
    same_state(&replay, &once);
    let second = heartbeat(&replay);
    replay.replay_candidate_commit(&second).unwrap();
    assert_eq!(replay.ledger.height, 2);
    assert_eq!(replay.ledger.anchor_supply, Amount::TOTAL_SUPPLY);
    assert_eq!(
        replay.ledger.value_risk_policy.current_cap,
        ValueCap::ValueCap0
    );
}

#[test]
fn unsigned_preview_executes_before_signature_and_rejects_substitution_atomically() {
    let replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let before = replay.clone();
    let signed = heartbeat(&replay).proposal;
    assert!(replay.check_unsigned_proposal(&signed).is_err());
    let mut unsigned = signed;
    unsigned.signature.clear();
    replay.check_unsigned_proposal(&unsigned).unwrap();
    let mut variants = Vec::new();
    let mut bad = unsigned.clone();
    bad.expected_state_root = "99".repeat(32);
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.expected_height += 1;
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.command_hash = "99".repeat(32);
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.round = 1;
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.proposer_public_key = validators()
        .into_iter()
        .find(|v| v.public_key != unsigned.proposer_public_key)
        .unwrap()
        .public_key;
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.parent_state_root = "99".repeat(32);
    variants.push(bad);
    let mut bad = unsigned.clone();
    bad.command = ConsensusCommand::ActivatePendingValueRiskPolicy;
    bad.command_hash = bad
        .command
        .wire_v1_command_hash("rldcoin:mainnet:v1")
        .unwrap();
    variants.push(bad);
    for bad in variants {
        assert!(replay.check_unsigned_proposal(&bad).is_err());
        same_state(&replay, &before);
    }
}

#[test]
fn complete_tag28_semantics_use_own_finalized_prefix_sources_and_sidecars() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let heartbeat = heartbeat(&replay);
    let anchor = AdmissionLedgerAnchorV1 {
        height: 1,
        block_id: AdmissionHash32::from_hex(
            &heartbeat.wire_v1_commit_hash("rldcoin:mainnet:v1").unwrap(),
        )
        .unwrap(),
    };
    let genesis = replay.manifest.admission_genesis().clone();
    let first = source(
        &genesis,
        &anchor,
        genesis.genesis_header,
        1,
        AdmissionWork::ZERO,
        true,
    );
    let before = replay.clone();
    assert!(replay
        .append_admission_source(&first)
        .unwrap_err()
        .contains("certified prefix"));
    same_state(&replay, &before);
    replay.replay_candidate_commit(&heartbeat).unwrap();
    replay.append_admission_source(&first).unwrap();
    let once = replay.clone();
    replay.append_admission_source(&first).unwrap();
    same_state(&replay, &once);
    let mut bad = first.clone();
    bad.entries[0].payload[0] ^= 1;
    assert!(replay.append_admission_source(&bad).is_err());
    same_state(&replay, &once);
    let mut sources = vec![first.clone()];
    let mut parent = first.header.header_id();
    let mut cumulative = first.header.cumulative_work;
    let mut incomplete = replay.clone();
    for height in 2..=33 {
        let submitted = source(&genesis, &anchor, parent, height, cumulative, height == 33);
        parent = submitted.header.header_id();
        cumulative = submitted.header.cumulative_work;
        if height == 33 {
            incomplete = replay.clone();
        }
        replay.append_admission_source(&submitted).unwrap();
        sources.push(submitted);
    }
    let proof = AdmissionCheckpointProofV1 {
        context: genesis.context.clone(),
        prior_committed_header: genesis.genesis_header,
        prior_checkpoint_accumulator: replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .checkpoint_accumulator,
        batch_segment: vec![replay
            .log
            .retained_header_batch(first.header.header_id())
            .unwrap()],
        confirmation_segment: sources[1..]
            .iter()
            .map(|s| AdmissionCheckpointConfirmationProofV1 {
                access_work: s.access_work.clone(),
                header: s.header.clone(),
                ledger_anchor: s.ledger_anchor.clone(),
            })
            .collect(),
    };
    let proposal = signed_proposal(
        &replay,
        ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof)),
    );
    let before = replay.clone();
    let mut unsigned = proposal.clone();
    unsigned.signature.clear();
    replay.check_unsigned_proposal(&unsigned).unwrap();
    assert!(incomplete.check_unsigned_proposal(&unsigned).is_err());
    unsigned.expected_state_root = "99".repeat(32);
    assert!(replay.check_unsigned_proposal(&unsigned).is_err());
    assert_eq!(
        replay.check_signed_proposal(&proposal).unwrap().command_tag,
        28
    );
    same_state(&replay, &before);
    assert!(incomplete.check_signed_proposal(&proposal).is_err());
    for submitted in [&first, sources.last().unwrap()] {
        let mut missing = replay.clone();
        missing
            .sidecars
            .remove(&submitted.entries[0].entry.payload_commitment);
        let missing_before = missing.clone();
        assert!(missing.check_signed_proposal(&proposal).is_err());
        same_state(&missing, &missing_before);
    }
    let commit = certificate(proposal);
    replay.replay_candidate_commit(&commit).unwrap();
    assert_eq!(replay.ledger.height, 2);
    assert_eq!(
        replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .checkpoint_count,
        1
    );
    assert_eq!(replay.log.committed_header(), first.header.header_id());
    assert_eq!(replay.ledger.anchor_supply, Amount::TOTAL_SUPPLY);
    let mut recovered = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    recovered.replay_candidate_commit(&heartbeat).unwrap();
    let mut frames = vec![ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(
        heartbeat.clone(),
    )))];
    for submitted in &sources {
        frames.push(ReplayFrame::new(ReplayEvent::AdmissionSource(Box::new(
            ReplayAdmissionSource::from(submitted),
        ))));
    }
    frames.push(ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(
        commit.clone(),
    ))));
    // Consume actual raw interchange bytes; the first heartbeat is an exact
    // retry because this instance already replayed it above.
    for frame in &frames {
        ReplayFrame::decode_line(&frame.canonical_line().unwrap())
            .unwrap()
            .replay(&mut recovered)
            .unwrap();
    }
    same_state(&replay, &recovered);
    let next = heartbeat_after(&replay);
    replay.check_signed_proposal(&next.proposal).unwrap();
    assert_eq!(
        replay
            .ledger
            .m0_active_protocol
            .as_ref()
            .unwrap()
            .upgrade_sequence,
        0
    );
    // Opt-in generation retains only public known-seed test material. Never
    // overwrites an existing fixture or includes a key/configuration database.
    if let Ok(destination) = std::env::var("RLD_CANDIDATE_REPLAY_FIXTURE_DIR") {
        let directory = std::path::Path::new(&destination);
        std::fs::create_dir(directory).unwrap();
        let mut transcript = Vec::new();
        for frame in frames {
            transcript.extend(frame.canonical_line().unwrap());
            transcript.push(b'\n');
        }
        std::fs::write(directory.join("history.jsonl"), transcript).unwrap();
        std::fs::write(directory.join("expected.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "manifest_sha256": PIN, "expected_height": "2", "expected_state_root": replay.ledger.state_root().unwrap(),
            "scope": "PUBLIC_KNOWN_SEED_DISPOSABLE_FIXTURE", "live_authorization": false,
        })).unwrap()).unwrap();
    }
}

fn heartbeat_after(replay: &M0CandidateReplay) -> ConsensusCommit {
    heartbeat(replay)
}

#[test]
fn source_retry_uses_the_same_canonical_entry_set_as_the_admission_log() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let commit = heartbeat(&replay);
    replay.replay_candidate_commit(&commit).unwrap();
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 1,
        block_id: *replay.anchors.get(&1).unwrap(),
    };
    let mut submitted = source(
        &genesis,
        &anchor,
        genesis.genesis_header,
        1,
        AdmissionWork::ZERO,
        true,
    );
    let second = source(
        &genesis,
        &anchor,
        genesis.genesis_header,
        2,
        AdmissionWork::ZERO,
        true,
    );
    submitted.entries.extend(second.entries);
    submitted
        .entries
        .sort_unstable_by_key(|s| std::cmp::Reverse(s.entry.entry_id()));
    let root = admission_entry_root(submitted.entries.iter().map(|s| s.entry.entry_id())).unwrap();
    submitted.access_work.entries_root = root;
    submitted.access_work.entries_count = 2;
    loop {
        submitted.access_work.output_hash = submitted.access_work.recompute_output_hash();
        if AdmissionWork::from_be_bytes(submitted.access_work.output_hash.0)
            <= submitted.access_work.target
        {
            break;
        }
        submitted.access_work.nonce += 1;
    }
    submitted.header.entries_root = root;
    submitted.header.entries_count = 2;
    submitted.header.access_work_id = submitted.access_work.work_id();
    submitted.header.cumulative_work = submitted.access_work.header_work();
    replay.append_admission_source(&submitted).unwrap();
    let before = replay.clone();
    replay.append_admission_source(&submitted).unwrap();
    same_state(&replay, &before);
    submitted.entries.reverse();
    replay.append_admission_source(&submitted).unwrap();
    same_state(&replay, &before);
    submitted.entries[1] = submitted.entries[0].clone();
    assert!(replay.append_admission_source(&submitted).is_err());
    same_state(&replay, &before);
}

#[test]
fn local_resource_exhaustion_does_not_prune_or_mutate_verified_state() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let commit = heartbeat(&replay);
    replay.retained_commit_bytes = MAX_M0_REPLAY_COMMIT_BYTES;
    let before = replay.clone();
    assert!(replay.replay_candidate_commit(&commit).is_err());
    same_state(&replay, &before);
    replay.retained_commit_bytes = 0;
    replay.replay_candidate_commit(&commit).unwrap();
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 1,
        block_id: *replay.anchors.get(&1).unwrap(),
    };
    let submitted = source(
        &genesis,
        &anchor,
        genesis.genesis_header,
        1,
        AdmissionWork::ZERO,
        true,
    );
    replay.sidecar_bytes = MAX_M0_REPLAY_SIDECAR_BYTES;
    let before = replay.clone();
    assert!(replay.append_admission_source(&submitted).is_err());
    same_state(&replay, &before);
    replay.sidecar_bytes = 0;
    replay.retained_headers = MAX_M0_REPLAY_HEADERS;
    let before = replay.clone();
    assert!(replay.append_admission_source(&submitted).is_err());
    same_state(&replay, &before);
}

#[test]
fn transcript_preserves_u128_and_rejects_unsigned_json_additions_duplicates_and_reordering() {
    let replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let frame = ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(heartbeat(&replay))));
    let canonical = String::from_utf8(frame.canonical_line().unwrap()).unwrap();
    let decoded = ReplayFrame::decode_line(canonical.as_bytes()).unwrap();
    assert_eq!(decoded.canonical_line().unwrap(), canonical.as_bytes());
    let unsigned_field = canonical.replacen(
        "\"proposal_id\":",
        "\"unsigned_override\":true,\"proposal_id\":",
        1,
    );
    assert!(ReplayFrame::decode_line(unsigned_field.as_bytes()).is_err());
    let duplicate = canonical.replacen(
        "\"parent_height\":0",
        "\"parent_height\":0,\"parent_height\":0",
        1,
    );
    assert!(ReplayFrame::decode_line(duplicate.as_bytes()).is_err());
    assert!(ReplayFrame::decode_line(format!(" {canonical}").as_bytes()).is_err());
    let genesis = replay.manifest.admission_genesis();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 1,
        block_id: AdmissionHash32([33; 32]),
    };
    let mut source = ReplayAdmissionSource::from(&source(
        genesis,
        &anchor,
        genesis.genesis_header,
        1,
        AdmissionWork::ZERO,
        false,
    ));
    source.ledger_anchor.height = u128::MAX;
    let frame = ReplayFrame::new(ReplayEvent::AdmissionSource(Box::new(source)));
    let line = frame.canonical_line().unwrap();
    let decoded = ReplayFrame::decode_line(&line).unwrap();
    let ReplayEvent::AdmissionSource(source) = decoded.event else {
        panic!("wrong event");
    };
    assert_eq!(source.ledger_anchor.height, u128::MAX);
}

fn observation_fixture() -> Vec<ReplayFrame> {
    include_bytes!("../../../../vectors/m0-semantic-replay-v1/history.jsonl")
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| ReplayFrame::decode_line(line).unwrap())
        .collect()
}

#[test]
fn admission_observation_requires_confirmations_and_finality_to_retire_prefix() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let birth = replay.observe_admission().unwrap();
    assert_eq!(birth.report().finalized_height, "0");
    assert_eq!(birth.report().finalized_commit_hash, None);
    assert_eq!(birth.report().confirmed_prefix, None);
    let frames = observation_fixture();
    for frame in &frames[..33] {
        frame.clone().replay(&mut replay).unwrap();
        assert_eq!(
            replay
                .observe_admission()
                .unwrap()
                .report()
                .confirmed_prefix,
            None
        );
    }
    frames[33].clone().replay(&mut replay).unwrap();
    let before = replay.clone();
    let observation = replay.observe_admission().unwrap();
    same_state(&replay, &before);
    let report = observation.report();
    let prefix = report.confirmed_prefix.as_ref().unwrap();
    let prepared = replay.log.build_confirmed_checkpoint(2).unwrap();
    assert_eq!(prefix.header_id, prepared.checkpoint.header_id.to_hex());
    assert_eq!(
        prefix.entries_root,
        prepared.checkpoint.entries_root.to_hex()
    );
    assert_eq!(
        prefix.availability_root,
        prepared.checkpoint.availability_root.to_hex()
    );
    assert_eq!(
        prefix.entry_ids,
        prepared
            .entry_ids
            .iter()
            .map(|id| id.to_hex())
            .collect::<Vec<_>>()
    );
    assert_eq!(prefix.confirmations, 32);
    assert_eq!(prefix.observed_ledger_height, "1");
    assert_eq!(prefix.finalized_lag_epochs, "0");
    assert!(prefix.next_block_within_lag_bound);
    assert!(!prefix.finalized_lag_exceeded);
    assert!(!report.signature_authorized && !report.live_censorship_policy_active);
    let ReplayEvent::CertifiedCommit(commit) = frames.last().unwrap().event.clone() else {
        panic!("commit")
    };
    let mut weak = commit.clone();
    weak.votes.truncate(2);
    assert!(replay.replay_candidate_commit(&weak).is_err());
    assert_eq!(replay.observe_admission().unwrap(), observation);
    same_state(&replay, &before);
    // A failed finality check cannot remove a confirmed prefix. Only the full
    // certified transition changes the committed Admission head.
    replay.replay_candidate_commit(&commit).unwrap();
    let retired = replay.observe_admission().unwrap();
    assert_eq!(retired.report().finalized_height, "2");
    assert_eq!(
        retired.report().committed_admission_header,
        prefix.header_id
    );
    assert_eq!(retired.report().confirmed_prefix, None);
}

#[test]
fn admission_observation_rechecks_batch_and_confirmation_sidecars_and_certified_clock() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let frames = observation_fixture();
    for frame in &frames[..34] {
        frame.clone().replay(&mut replay).unwrap();
    }
    assert_eq!(replay.sidecars.len(), 2);
    for key in replay.sidecars.keys() {
        let mut missing = replay.clone();
        missing.sidecars.remove(key);
        let before = missing.clone();
        assert!(missing.observe_admission().unwrap_err().contains("sidecar"));
        same_state(&missing, &before);
        let mut corrupt = replay.clone();
        corrupt
            .sidecars
            .insert(*key, Arc::new(b"false availability".to_vec()));
        assert!(corrupt.observe_admission().is_err());
    }
    let mut unproven_clock = replay.clone();
    unproven_clock.ledger.height = 192;
    assert!(unproven_clock
        .observe_admission()
        .unwrap_err()
        .contains("certified commit"));
    let mut absent_anchor = replay.clone();
    absent_anchor.anchors.clear();
    assert!(absent_anchor.observe_admission().is_err());
    let mut inconsistent = replay.clone();
    inconsistent
        .ledger
        .admission_state
        .as_mut()
        .unwrap()
        .committed_header = AdmissionHash32([55; 32]);
    // Genesis/Ledger validation may reject this before the additional log
    // projection check; either way no verified capability can be created.
    assert!(inconsistent.observe_admission().is_err());
}

#[test]
fn admission_observation_aged_prefix_uses_certified_epoch_and_keeps_lag_guard() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &observation_fixture()[..34] {
        frame.clone().replay(&mut replay).unwrap();
    }
    let prefix = replay
        .observe_admission()
        .unwrap()
        .report()
        .confirmed_prefix
        .clone()
        .unwrap();
    let mut history = Vec::new();
    while replay.ledger.height < 192 {
        let commit = heartbeat(&replay);
        replay.replay_candidate_commit(&commit).unwrap();
        history.extend(serde_json::to_vec(&commit).unwrap());
        history.push(b'\n');
        if replay.ledger.height == 191 {
            let current = replay.observe_admission().unwrap();
            let current = current.report().confirmed_prefix.as_ref().unwrap();
            assert_eq!(current.finalized_lag_epochs, "2");
            assert!(!current.finalized_lag_exceeded);
            assert!(!current.next_block_within_lag_bound);
        }
    }
    let before = replay.clone();
    let aged = replay.observe_admission().unwrap();
    same_state(&replay, &before);
    assert_eq!(aged.report().finalized_epoch, "3");
    let aged = aged.report().confirmed_prefix.as_ref().unwrap();
    assert_eq!(aged.header_id, prefix.header_id);
    assert_eq!(aged.entries_root, prefix.entries_root);
    assert_eq!(aged.entry_ids, prefix.entry_ids);
    assert_eq!(aged.observed_ledger_height, "1");
    assert_eq!(aged.finalized_lag_epochs, "3");
    assert!(aged.finalized_lag_exceeded);
    assert!(!aged.next_block_within_lag_bound);
    assert!(replay
        .log
        .build_confirmed_checkpoint(193)
        .unwrap_err()
        .to_string()
        .contains("two-Epoch"));
    // Public fixture keys only. Emit actual certified progress for the binary
    // service/restart test; this optional output cannot affect assertions.
    if let Some(path) = std::env::var_os("RLD_OBSERVATION_AGED_HISTORY_OUT") {
        std::fs::write(path, history).unwrap();
    }
}

fn inclusion_fixture_ids() -> (AdmissionHash32, AdmissionHash32) {
    let frames = observation_fixture();
    let id = |frame: &ReplayFrame| {
        let ReplayEvent::AdmissionSource(source) = &frame.event else {
            panic!("source")
        };
        source.entries[0].entry.entry_id()
    };
    (id(&frames[1]), id(&frames[33]))
}

fn observed_fixture() -> (M0CandidateReplay, Vec<ReplayFrame>) {
    let frames = observation_fixture()[..34].to_vec();
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames {
        frame.clone().replay(&mut replay).unwrap();
    }
    (replay, frames)
}

fn commit_source_branch(
    replay: &M0CandidateReplay,
    sources: &[AdmissionVerifiedHeaderSubmissionV1],
) -> ConsensusCommit {
    let split = sources.len() - MIN_ADMISSION_CONFIRMATIONS;
    let proof = AdmissionCheckpointProofV1 {
        context: replay.manifest.admission_genesis().context.clone(),
        prior_committed_header: replay.log.committed_header(),
        prior_checkpoint_accumulator: replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .checkpoint_accumulator,
        batch_segment: sources[..split]
            .iter()
            .map(|s| {
                replay
                    .log
                    .retained_header_batch(s.header.header_id())
                    .unwrap()
            })
            .collect(),
        confirmation_segment: sources[split..]
            .iter()
            .map(|s| AdmissionCheckpointConfirmationProofV1 {
                header: s.header.clone(),
                access_work: s.access_work.clone(),
                ledger_anchor: s.ledger_anchor.clone(),
            })
            .collect(),
    };
    certificate(signed_proposal(
        replay,
        ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof)),
    ))
}

#[test]
fn observation_reconciliation_joins_original_finality_without_promoting_pending_sources() {
    use reconciliation::ObservedEntryDisposition::*;
    let (mut replay, _) = observed_fixture();
    let observed = replay.observe_admission().unwrap();
    let before = replay.clone();
    let pending = replay
        .reconcile_admission_observation(&observed)
        .unwrap()
        .report();
    assert!(!pending.all_observed_entries_included);
    assert_eq!(pending.entries.len(), 1);
    assert_eq!(pending.entries[0].disposition, UnresolvedCanonical);
    assert!(pending.entries[0].in_next_confirmed_batch);
    assert!(pending.entries[0].inclusion.is_none());
    let ReplayEvent::CertifiedCommit(commit) = &observation_fixture()[34].event else {
        panic!("commit");
    };
    replay.check_signed_proposal(&commit.proposal).unwrap();
    assert_eq!(
        replay
            .reconcile_admission_observation(&observed)
            .unwrap()
            .report(),
        pending
    );
    same_state(&replay, &before);
    replay.replay_candidate_commit(commit).unwrap();
    let treated = replay.reconcile_admission_observation(&observed).unwrap();
    assert_eq!(
        treated.entries()[0].inclusion().unwrap().certificate(),
        commit.as_ref()
    );
    let resolved = treated.report();
    assert!(resolved.all_observed_entries_included);
    assert_eq!(resolved.entries[0].disposition, FinalizedCheckpoint);
    assert_eq!(
        resolved.entries[0].obligation_id,
        pending.entries[0].obligation_id
    );
    assert!(!resolved.entries[0].in_next_confirmed_batch);
    assert!(!resolved.recovery_authorized && !resolved.live_authorization);
    let following = heartbeat(&replay);
    replay.replay_candidate_commit(&following).unwrap();
    let later = replay
        .reconcile_admission_observation(&observed)
        .unwrap()
        .report();
    assert_eq!(later.entries, resolved.entries);
    assert_eq!(later.current_finalized_height, "3");
    assert_eq!(later.observed_at_finalized_height, "1");
    assert_eq!(
        later.entries[0]
            .inclusion
            .as_ref()
            .unwrap()
            .finalized_height,
        "2"
    );
}

#[test]
fn observation_reconciliation_requires_origin_ancestry_and_complete_retained_dependencies() {
    let (mut replay, _) = observed_fixture();
    let observed = replay.observe_admission().unwrap();
    let birth = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    assert!(birth
        .reconcile_admission_observation(&observed)
        .unwrap_err()
        .contains("future"));
    assert!(replay
        .reconcile_admission_observation(&birth.observe_admission().unwrap())
        .unwrap_err()
        .contains("no confirmed entries"));
    let mut fork = birth.clone();
    let mut command = heartbeat(&fork).proposal.command;
    let ConsensusCommand::NetworkHeartbeat(ref mut heartbeat) = command else {
        unreachable!()
    };
    heartbeat.note_hash = hash_bytes(b"different certified history");
    fork.replay_candidate_commit(&certificate(signed_proposal(&fork, command)))
        .unwrap();
    assert!(fork
        .reconcile_admission_observation(&observed)
        .unwrap_err()
        .contains("conflicts"));
    observation_fixture()[34]
        .clone()
        .replay(&mut replay)
        .unwrap();
    let ReplayEvent::AdmissionSource(confirming) = &observation_fixture()[33].event else {
        panic!("source");
    };
    // The observed entry is included, but its original confirming header had a
    // different payload. Losing that payload cannot leave a cached success.
    let mut missing = replay.clone();
    missing
        .sidecars
        .remove(&confirming.entries[0].entry.payload_commitment);
    let before = missing.clone();
    assert!(missing
        .reconcile_admission_observation(&observed)
        .unwrap_err()
        .contains("sidecar"));
    same_state(&missing, &before);
    let mut no_clock = replay.clone();
    no_clock
        .ledger
        .consensus_commits
        .remove(&no_clock.anchors[&1].to_hex());
    assert!(no_clock
        .reconcile_admission_observation(&observed)
        .unwrap_err()
        .contains("certificate"));
    let (other, _) = observed_fixture();
    assert!(replay
        .reconcile_admission_observation(&other.observe_admission().unwrap())
        .unwrap()
        .all_observed_entries_included());
}

#[test]
fn observation_reconciliation_identity_survives_clock_and_confirmed_batch_growth() {
    let (mut replay, frames) = observed_fixture();
    let original = replay.observe_admission().unwrap();
    let old_id = replay
        .reconcile_admission_observation(&original)
        .unwrap()
        .entries()[0]
        .obligation_id();
    let progress = heartbeat(&replay);
    replay.replay_candidate_commit(&progress).unwrap();
    let later = replay.observe_admission().unwrap();
    assert_ne!(
        later.report().finalized_height,
        original.report().finalized_height
    );
    assert_eq!(
        replay
            .reconcile_admission_observation(&later)
            .unwrap()
            .entries()[0]
            .obligation_id(),
        old_id
    );
    let mut sources: Vec<_> = frames
        .iter()
        .filter_map(|f| match &f.event {
            ReplayEvent::AdmissionSource(s) => Some(s.clone().into_submission()),
            _ => None,
        })
        .collect();
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 2,
        block_id: replay.anchors[&2],
    };
    for height in 34..=65 {
        let last = sources.last().unwrap();
        let next = source(
            &genesis,
            &anchor,
            last.header.header_id(),
            height,
            last.header.cumulative_work,
            false,
        );
        replay.append_admission_source(&next).unwrap();
        sources.push(next);
    }
    let grown = replay.observe_admission().unwrap();
    assert_eq!(
        grown
            .report()
            .confirmed_prefix
            .as_ref()
            .unwrap()
            .entry_ids
            .len(),
        2
    );
    assert_ne!(
        grown.report().confirmed_prefix.as_ref().unwrap().header_id,
        original
            .report()
            .confirmed_prefix
            .as_ref()
            .unwrap()
            .header_id
    );
    let resolved_old = replay
        .reconcile_admission_observation(&original)
        .unwrap()
        .report();
    let grown_report = replay
        .reconcile_admission_observation(&grown)
        .unwrap()
        .report();
    let original_entry = inclusion_fixture_ids().0.to_hex();
    assert_eq!(
        grown_report
            .entries
            .iter()
            .find(|e| e.entry_id == original_entry)
            .unwrap()
            .obligation_id,
        old_id.to_hex()
    );
    assert_eq!(resolved_old.entries.len(), 1);
    replay
        .replay_candidate_commit(&commit_source_branch(&replay, &sources))
        .unwrap();
    assert!(replay
        .reconcile_admission_observation(&original)
        .unwrap()
        .all_observed_entries_included());
    assert!(replay
        .reconcile_admission_observation(&grown)
        .unwrap()
        .all_observed_entries_included());
}

#[test]
fn observation_reconciliation_keeps_reorged_entries_unresolved_and_relocates_same_entry() {
    use reconciliation::ObservedEntryDisposition::*;
    let (mut replay, mut frames) = observed_fixture();
    let original = replay.observe_admission().unwrap();
    let original_fact = replay
        .reconcile_admission_observation(&original)
        .unwrap()
        .report()
        .entries[0]
        .clone();
    let progress = heartbeat(&replay);
    replay.replay_candidate_commit(&progress).unwrap();
    frames.push(ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(
        progress,
    ))));
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 2,
        block_id: replay.anchors[&2],
    };
    let mut reorged_frames = Vec::new();
    for (length, include_original_entry) in [(34, false), (35, true)] {
        let mut branch = Vec::new();
        let mut parent = genesis.genesis_header;
        let mut work = AdmissionWork::ZERO;
        for height in 1..=length {
            let next = source(
                &genesis,
                &anchor,
                parent,
                height,
                work,
                include_original_entry && height == 1,
            );
            parent = next.header.header_id();
            work = next.header.cumulative_work;
            replay.append_admission_source(&next).unwrap();
            frames.push(ReplayFrame::new(ReplayEvent::AdmissionSource(Box::new(
                ReplayAdmissionSource::from(&next),
            ))));
            branch.push(next);
        }
        let report = replay
            .reconcile_admission_observation(&original)
            .unwrap()
            .report();
        assert_eq!(report.entries[0].obligation_id, original_fact.obligation_id);
        let obligations = replay
            .admission_obligations(&obligations::AdmissionObligationQuery::default())
            .unwrap();
        assert_eq!(obligations.total_observed_entries, 1);
        assert_eq!(
            obligations.entries[0].first_confirmed_at_finalized_height,
            "1"
        );
        assert_eq!(
            obligations.entries[0].treatment.disposition,
            report.entries[0].disposition
        );

        assert!(!report.all_observed_entries_included && !report.recovery_authorized);
        if !include_original_entry {
            assert_eq!(report.entries[0].disposition, UnresolvedReorged);
            assert!(!report.entries[0].in_next_confirmed_batch);
            reorged_frames = frames.clone();
        } else {
            assert_eq!(report.entries[0].disposition, UnresolvedCanonical);
            assert!(report.entries[0].in_next_confirmed_batch);
            let relocated = replay.observe_admission().unwrap();
            assert_eq!(
                replay
                    .reconcile_admission_observation(&relocated)
                    .unwrap()
                    .report()
                    .entries[0]
                    .obligation_id,
                original_fact.obligation_id
            );
            let commit = commit_source_branch(&replay, &branch);
            replay.replay_candidate_commit(&commit).unwrap();
            frames.push(ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(
                commit,
            ))));
        }
    }
    let resolved = replay
        .reconcile_admission_observation(&original)
        .unwrap()
        .report();
    assert!(resolved.all_observed_entries_included);
    assert_eq!(resolved.entries[0].disposition, FinalizedCheckpoint);
    assert_ne!(
        resolved.entries[0].observed_source_header,
        resolved.entries[0]
            .inclusion
            .as_ref()
            .unwrap()
            .source_header_id
    );
    let mut recovered = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let mut recovered_observation = None;
    for (i, frame) in frames.iter().enumerate() {
        frame.clone().replay(&mut recovered).unwrap();
        if i == 33 {
            recovered_observation = Some(recovered.observe_admission().unwrap());
        }
    }
    assert_eq!(
        recovered
            .reconcile_admission_observation(&recovered_observation.unwrap())
            .unwrap()
            .report(),
        resolved
    );
    same_state(&replay, &recovered);
    if let Some(directory) = std::env::var_os("RLD_RECONCILIATION_FIXTURE_OUT") {
        let directory = std::path::PathBuf::from(directory);
        assert!(
            directory.is_absolute(),
            "evidence output must be outside the crate source tree at an explicit absolute path"
        );
        std::fs::create_dir_all(&directory).unwrap();
        for (name, history) in [("reorged", &reorged_frames), ("relocated-final", &frames)] {
            let mut bytes = Vec::new();
            let mut verifier = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
            let mut captured = None;
            for (i, frame) in history.iter().enumerate() {
                bytes.extend(frame.canonical_line().unwrap());
                bytes.push(b'\n');
                frame.clone().replay(&mut verifier).unwrap();
                if i == 33 {
                    captured = Some(verifier.observe_admission().unwrap());
                }
            }
            let report = verifier
                .reconcile_admission_observation(&captured.unwrap())
                .unwrap()
                .report();
            std::fs::write(directory.join(format!("{name}-history.jsonl")), bytes).unwrap();
            std::fs::write(directory.join(format!("{name}-expected.json")), serde_json::to_vec_pretty(&serde_json::json!({
                "public_fixture_keys_only": true, "observation_record": 34, "records": history.len(),
                "expected_height": verifier.ledger.height.to_string(), "expected_state_root": verifier.ledger.state_root().unwrap(),
                "reconciliation": report,
            })).unwrap()).unwrap();
        }
    }
}

#[test]
fn finalized_inclusion_requires_executed_full_qc_not_sources_or_proposal() {
    let frames = observation_fixture();
    let (included, confirming) = inclusion_fixture_ids();
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames[..34] {
        frame.clone().replay(&mut replay).unwrap();
    }
    assert!(replay
        .verified_admission_inclusion(included)
        .unwrap()
        .is_none());
    let ReplayEvent::CertifiedCommit(commit) = &frames[34].event else {
        panic!("commit")
    };
    replay.check_signed_proposal(&commit.proposal).unwrap();
    assert!(replay
        .verified_admission_inclusion(included)
        .unwrap()
        .is_none());
    let before = replay.clone();
    let mut weak = commit.clone();
    weak.votes.truncate(2);
    assert!(replay.replay_candidate_commit(&weak).is_err());
    same_state(&replay, &before);
    let mut false_root = commit.clone();
    false_root.proposal.expected_state_root = "55".repeat(32);
    assert!(replay.replay_candidate_commit(&false_root).is_err());
    same_state(&replay, &before);
    replay.replay_candidate_commit(commit).unwrap();
    let once = replay.clone();
    let fact = replay
        .verified_admission_inclusion(included)
        .unwrap()
        .unwrap();
    assert_eq!(fact.certificate(), commit.as_ref());
    assert_eq!(fact.entry().entry_id(), included);
    assert_eq!(
        fact.checkpoint(),
        replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .latest_checkpoint
            .as_ref()
            .unwrap()
    );
    let report = fact.report();
    assert_eq!(report.finalized_height, "2");
    assert_eq!(
        report.finalized_commit_hash,
        commit.wire_v1_commit_hash("rldcoin:mainnet:v1").unwrap()
    );
    assert!(
        !report.contribution_accepted && !report.recovery_authorized && !report.live_authorization
    );
    // Confirmation headers and their available entries are not consumed by
    // this checkpoint; they cannot acquire finalized membership by proximity.
    assert!(replay
        .verified_admission_inclusion(confirming)
        .unwrap()
        .is_none());
    assert!(replay
        .verified_admission_inclusion(AdmissionHash32([99; 32]))
        .unwrap()
        .is_none());
    assert!(replay
        .verified_admission_inclusion(AdmissionHash32::ZERO)
        .is_err());
    same_state(&replay, &once);
    replay.replay_candidate_commit(commit).unwrap();
    same_state(&replay, &once);
    let mut recovered = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in frames {
        frame.replay(&mut recovered).unwrap();
    }
    same_state(&replay, &recovered);
    let next = heartbeat(&replay);
    replay.replay_candidate_commit(&next).unwrap();
    assert_eq!(
        replay
            .verified_admission_inclusion(included)
            .unwrap()
            .unwrap()
            .report(),
        report
    );
}

#[test]
fn finalized_inclusion_rechecks_retained_source_and_certificate_dependencies() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in observation_fixture() {
        frame.replay(&mut replay).unwrap();
    }
    let (included, _) = inclusion_fixture_ids();
    let payload = replay
        .verified_admission_inclusion(included)
        .unwrap()
        .unwrap()
        .entry()
        .payload_commitment;
    let mut missing = replay.clone();
    missing.sidecars.remove(&payload);
    assert!(missing
        .verified_admission_inclusion(included)
        .unwrap_err()
        .contains("sidecar"));
    let mut corrupt = replay.clone();
    corrupt
        .sidecars
        .insert(payload, Arc::new(b"wrong bytes".to_vec()));
    assert!(corrupt.verified_admission_inclusion(included).is_err());
    let mut no_anchor = replay.clone();
    no_anchor.anchors.remove(&2);
    assert!(no_anchor.verified_admission_inclusion(included).is_err());
    let mut no_certificate = replay.clone();
    no_certificate
        .ledger
        .consensus_commits
        .remove(&replay.anchors[&2].to_hex());
    assert!(no_certificate
        .verified_admission_inclusion(included)
        .is_err());
}

#[test]
fn finalized_inclusion_preserves_original_certificate_across_successor_checkpoints() {
    let mut frames = observation_fixture();
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames {
        frame.clone().replay(&mut replay).unwrap();
    }
    let (first, second) = inclusion_fixture_ids();
    let first_report = replay
        .verified_admission_inclusion(first)
        .unwrap()
        .unwrap()
        .report();
    let old_sources: Vec<_> = frames
        .iter()
        .filter_map(|f| match &f.event {
            ReplayEvent::AdmissionSource(s) => Some(s.clone().into_submission()),
            _ => None,
        })
        .collect();
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 2,
        block_id: replay.anchors[&2],
    };
    let mut parent = old_sources.last().unwrap().header.header_id();
    let mut work = old_sources.last().unwrap().header.cumulative_work;
    let mut confirming = Vec::new();
    for height in 34..=65 {
        let next = source(&genesis, &anchor, parent, height, work, false);
        parent = next.header.header_id();
        work = next.header.cumulative_work;
        replay.append_admission_source(&next).unwrap();
        frames.push(ReplayFrame::new(ReplayEvent::AdmissionSource(Box::new(
            ReplayAdmissionSource::from(&next),
        ))));
        confirming.push(AdmissionCheckpointConfirmationProofV1 {
            access_work: next.access_work,
            header: next.header,
            ledger_anchor: next.ledger_anchor,
        });
    }
    assert!(replay
        .verified_admission_inclusion(second)
        .unwrap()
        .is_none());
    let proof = AdmissionCheckpointProofV1 {
        context: genesis.context,
        prior_committed_header: replay.log.committed_header(),
        prior_checkpoint_accumulator: replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .checkpoint_accumulator,
        batch_segment: old_sources[1..]
            .iter()
            .map(|s| {
                replay
                    .log
                    .retained_header_batch(s.header.header_id())
                    .unwrap()
            })
            .collect(),
        confirmation_segment: confirming,
    };
    let commit = certificate(signed_proposal(
        &replay,
        ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof)),
    ));
    replay.replay_candidate_commit(&commit).unwrap();
    frames.push(ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(
        commit.clone(),
    ))));
    assert_eq!(
        replay
            .verified_admission_inclusion(first)
            .unwrap()
            .unwrap()
            .report(),
        first_report
    );
    let second_report = replay
        .verified_admission_inclusion(second)
        .unwrap()
        .unwrap()
        .report();
    assert_eq!(second_report.finalized_height, "3");
    let page1 = replay
        .admission_obligations(&obligations::AdmissionObligationQuery {
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(page1.total_observed_entries, 2);
    assert!(page1.next_after_entry_id.is_some());
    let page2 = replay
        .admission_obligations(&obligations::AdmissionObligationQuery {
            limit: 1,
            after_entry_id: page1.next_after_entry_id.clone(),
        })
        .unwrap();
    assert!(page2.next_after_entry_id.is_none());
    assert_ne!(page1.entries[0].entry_id, page2.entries[0].entry_id);
    assert_eq!(
        page1.entries[0].treatment.disposition,
        reconciliation::ObservedEntryDisposition::FinalizedCheckpoint
    );
    assert_eq!(
        page2.entries[0].treatment.disposition,
        reconciliation::ObservedEntryDisposition::FinalizedCheckpoint
    );

    assert_ne!(second_report.checkpoint_id, first_report.checkpoint_id);
    assert_eq!(
        second_report.finalized_commit_hash,
        commit.wire_v1_commit_hash("rldcoin:mainnet:v1").unwrap()
    );
    let mut recovered = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames {
        frame.clone().replay(&mut recovered).unwrap();
    }
    same_state(&replay, &recovered);
    if let Some(directory) = std::env::var_os("RLD_FINALIZED_INCLUSION_FIXTURE_OUT") {
        let directory = std::path::PathBuf::from(directory);
        assert!(
            directory.is_absolute(),
            "evidence output must be outside the crate source tree at an explicit absolute path"
        );
        std::fs::create_dir_all(&directory).unwrap();
        let mut transcript = Vec::new();
        for frame in frames {
            transcript.extend(frame.canonical_line().unwrap());
            transcript.push(b'\n');
        }
        std::fs::write(directory.join("history.jsonl"), transcript).unwrap();
        std::fs::write(
            directory.join("expected.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "first_entry": first.to_hex(), "second_entry": second.to_hex(),
                "expected_height":"3", "expected_state_root":replay.ledger.state_root().unwrap(),
                "inclusions":[first_report,second_report], "public_fixture_keys_only":true,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn admission_obligations_use_first_confirmed_local_head_not_source_anchor_or_query_time() {
    use obligations::AdmissionObligationQuery;
    let frames = observation_fixture();
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames[..33] {
        frame.clone().replay(&mut replay).unwrap();
    }
    assert_eq!(
        replay
            .admission_obligations(&AdmissionObligationQuery::default())
            .unwrap()
            .total_observed_entries,
        0
    );
    let h2 = heartbeat(&replay);
    replay.replay_candidate_commit(&h2).unwrap();
    frames[33].clone().replay(&mut replay).unwrap();
    let first = replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .unwrap();
    assert_eq!(first.total_observed_entries, 1);
    assert_eq!(first.entries[0].first_confirmed_at_finalized_height, "2");
    assert_eq!(
        replay
            .observe_admission()
            .unwrap()
            .report()
            .confirmed_prefix
            .as_ref()
            .unwrap()
            .observed_ledger_height,
        "1"
    );
    let h3 = heartbeat(&replay);
    replay.replay_candidate_commit(&h3).unwrap();
    for frame in &frames[1..34] {
        frame.clone().replay(&mut replay).unwrap();
    }
    let later = replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .unwrap();
    assert_eq!(later.entries[0].first_confirmed_at_finalized_height, "2");
    assert_eq!(
        later.entries[0].obligation_id,
        first.entries[0].obligation_id
    );
    if let Some(directory) = std::env::var_os("RLD_OBLIGATION_PROGRESS_FIXTURE_OUT") {
        let directory = std::path::PathBuf::from(directory);
        assert!(
            directory.is_absolute(),
            "evidence output must be outside the crate source tree at an explicit absolute path"
        );
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("heartbeat-2.json"),
            serde_json::to_vec(&h2).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("heartbeat-3.json"),
            serde_json::to_vec(&h3).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("expected.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "manifest_sha256": PIN, "first": first, "later": later, "public_fixture_keys_only": true,
        })).unwrap()).unwrap();
    }
    while replay.ledger().height < 192 {
        let next = heartbeat(&replay);
        replay.replay_candidate_commit(&next).unwrap();
    }
    let before = replay.clone();
    let aged = replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .unwrap();
    assert_eq!(aged.entries[0].elapsed_confirmed_epochs, "3");
    assert!(aged.entries[0].past_observation_lag_limit);
    assert_eq!(aged.entries[0].first_confirmed_at_finalized_height, "2");
    assert!(
        !aged.live_censorship_policy_active
            && !aged.contribution_eligibility_verified
            && !aged.objective_rejections_evaluated
    );
    same_state(&replay, &before);
}

#[test]
fn admission_obligations_capture_and_query_limits_leave_all_state_unchanged() {
    use obligations::*;
    let frames = observation_fixture();
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames[..33] {
        frame.clone().replay(&mut replay).unwrap();
    }
    replay.admission_obligations.dependency_bytes = MAX_OBLIGATION_DEPENDENCY_BYTES;
    let before = replay.clone();
    assert!(frames[33]
        .clone()
        .replay(&mut replay)
        .unwrap_err()
        .contains("obligation dependency limit"));
    same_state(&replay, &before);
    replay.admission_obligations.dependency_bytes = 0;
    frames[33].clone().replay(&mut replay).unwrap();
    let before = replay.clone();
    for query in [
        AdmissionObligationQuery {
            limit: 0,
            ..Default::default()
        },
        AdmissionObligationQuery {
            limit: 33,
            ..Default::default()
        },
        AdmissionObligationQuery {
            after_entry_id: Some("00".repeat(32)),
            ..Default::default()
        },
        AdmissionObligationQuery {
            after_entry_id: Some("AA".repeat(32)),
            ..Default::default()
        },
    ] {
        assert!(replay.admission_obligations(&query).is_err());
    }
    assert!(serde_json::from_str::<AdmissionObligationQuery>(r#"{"limit":1,"limit":2}"#).is_err());
    assert!(
        serde_json::from_str::<AdmissionObligationQuery>(r#"{"finalized_height":"0"}"#).is_err()
    );
    same_state(&replay, &before);
    let scope = replay.observe_admission().unwrap();
    let key = replay
        .log
        .retained_header_batch(scope.source_headers[0])
        .unwrap()
        .entries[0]
        .payload_commitment;
    replay.sidecars.remove(&key);
    assert!(replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .is_err());
}

#[test]
fn admission_obligations_resolve_only_after_full_finality_and_rebuild_from_ordered_history() {
    use obligations::*;
    let (mut replay, _) = observed_fixture();
    let frames = observation_fixture();
    let before = replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .unwrap();
    let ReplayEvent::CertifiedCommit(commit) = &frames.last().unwrap().event else {
        panic!("commit");
    };
    replay.check_signed_proposal(&commit.proposal).unwrap();
    assert_eq!(
        replay
            .admission_obligations(&AdmissionObligationQuery::default())
            .unwrap(),
        before
    );
    let mut weak = commit.clone();
    weak.votes.truncate(2);
    let unchanged = replay.clone();
    assert!(replay.replay_candidate_commit(&weak).is_err());
    same_state(&replay, &unchanged);
    replay.replay_candidate_commit(commit).unwrap();
    let resolved = replay
        .admission_obligations(&AdmissionObligationQuery::default())
        .unwrap();
    assert_eq!(resolved.total_observed_entries, 1);
    assert_eq!(
        resolved.entries[0].treatment.disposition,
        reconciliation::ObservedEntryDisposition::FinalizedCheckpoint
    );
    assert_eq!(resolved.entries[0].first_confirmed_at_finalized_height, "1");
    let mut restarted = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in frames {
        frame.replay(&mut restarted).unwrap();
    }
    assert_eq!(
        restarted
            .admission_obligations(&AdmissionObligationQuery::default())
            .unwrap(),
        resolved
    );
}

#[test]
fn staged_proposal_reference_reconstructs_exact_signed_command_and_rejects_substitution() {
    use super::proposal_reference::AdmissionProposalReferenceV1;
    let frames: Vec<_> = include_bytes!("../../../../vectors/m0-semantic-replay-v1/history.jsonl")
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(|b| ReplayFrame::decode_line(b).unwrap())
        .collect();
    let ReplayEvent::CertifiedCommit(commit) = &frames.last().unwrap().event else {
        panic!("commit");
    };
    let ConsensusCommand::CommitAdmissionCheckpoint(proof) = &commit.proposal.command else {
        panic!("proof");
    };
    let bytes = proof.canonical_bytes().unwrap();
    let reference = AdmissionProposalReferenceV1::from_proposal(&commit.proposal).unwrap();
    if let Ok(output) = std::env::var("RLD_SMALL_STAGED_PROOF_FIXTURE_OUT") {
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("proof.wire"), &bytes).unwrap();
        std::fs::write(
            output.join("proposal.json"),
            serde_json::to_vec(&commit.proposal).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("reference.json"),
            serde_json::to_vec(&reference).unwrap(),
        )
        .unwrap();
        let ReplayEvent::CertifiedCommit(heartbeat) = &frames[0].event else {
            panic!("heartbeat")
        };
        std::fs::write(
            output.join("heartbeat.json"),
            serde_json::to_vec(heartbeat).unwrap(),
        )
        .unwrap();
        let mut count = 0;
        for frame in &frames {
            if let ReplayEvent::AdmissionSource(source) = &frame.event {
                std::fs::write(
                    output.join(format!("source-{count:04}.frame")),
                    super::source_frame::encode_source_frame(&source.clone().into_submission())
                        .unwrap(),
                )
                .unwrap();
                count += 1;
            }
        }
        std::fs::write(
            output.join("expected.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "manifest_sha256": PIN, "proof_bytes": bytes.len(), "source_headers":count,
                "proof_id":proof.proof_id().unwrap().to_hex(),
                "expected_height":commit.proposal.expected_height,
                "expected_state_root":commit.proposal.expected_state_root,
                "public_fixture_keys_only":true, "signature_authorized":false
            }))
            .unwrap(),
        )
        .unwrap();
    }
    let resolved = reference.resolve(&bytes).unwrap();
    assert_eq!(
        serde_json::to_vec(&resolved).unwrap(),
        serde_json::to_vec(&commit.proposal).unwrap()
    );
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in &frames[..frames.len() - 1] {
        frame.clone().replay(&mut replay).unwrap();
    }
    let before = replay.clone();
    replay.check_signed_proposal(&resolved).unwrap();
    let mut wrong = reference.clone();
    wrong.proof_id = "11".repeat(32);
    assert!(wrong.resolve(&bytes).is_err());
    wrong = reference.clone();
    wrong.command_hash = "22".repeat(32);
    assert!(wrong.resolve(&bytes).is_err());
    wrong = reference.clone();
    wrong.zone_id.push('x');
    assert!(wrong.resolve(&bytes).is_err());
    wrong = reference.clone();
    wrong.signature = "00".repeat(64);
    let forged = wrong.resolve(&bytes).unwrap();
    assert!(replay.check_signed_proposal(&forged).is_err());
    wrong = reference.clone();
    wrong.proposal_id = "x".repeat(4096);
    assert!(wrong.proof_id_bytes().is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(reference.resolve(&trailing).is_err());
    let mut json = serde_json::to_value(&reference).unwrap();
    json["command"] = "NetworkHeartbeat".into();
    assert!(serde_json::from_value::<AdmissionProposalReferenceV1>(json).is_err());
    let raw = serde_json::to_string(&reference).unwrap();
    let duplicate = format!("{{\"proof_id\":\"{}\",{}", reference.proof_id, &raw[1..]);
    assert!(serde_json::from_str::<AdmissionProposalReferenceV1>(&duplicate).is_err());
    same_state(&replay, &before);
}

#[test]
fn staged_proposal_reference_large_valid_proof_crosses_inline_limits() {
    use super::proposal_reference::AdmissionProposalReferenceV1;
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    let first = heartbeat(&replay);
    replay.replay_candidate_commit(&first).unwrap();
    let genesis = replay.manifest.admission_genesis().clone();
    let anchor = AdmissionLedgerAnchorV1 {
        height: 1,
        block_id: AdmissionHash32::from_hex(
            &first
                .wire_v1_commit_hash(&genesis.context.network_domain)
                .unwrap(),
        )
        .unwrap(),
    };
    let mut parent = genesis.genesis_header;
    let mut cumulative = AdmissionWork::ZERO;
    let template = source(&genesis, &anchor, parent, 1, cumulative, true)
        .entries
        .remove(0);
    let owner = identity(15);
    let mut sources = Vec::new();
    for height in 1..=1024u128 {
        let mut submitted = source(&genesis, &anchor, parent, height, cumulative, false);
        let count = if height <= 2 {
            256
        } else if height == 513 {
            1
        } else {
            0
        };
        for i in 0..count {
            let payload = format!("maximum-proof-{height}-{i}").into_bytes();
            let mut entry = template.entry.clone();
            entry.payload_commitment = admission_sidecar_payload_commitment(&payload).unwrap();
            entry.declared_bytes = payload.len() as u64;
            entry.locator_commitment = admission_sidecar_locator_commitment(
                entry.payload_commitment,
                entry.declared_bytes,
            );
            entry.entry_signature = AdmissionSignature64(
                hex::decode(sign_bytes(&owner.secret_key, &entry.signing_subject().0).unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            submitted
                .entries
                .push(AdmissionSidecarSubmissionV1 { entry, payload });
        }
        submitted.entries.sort_by_key(|e| e.entry.entry_id());
        let root =
            admission_entry_root(submitted.entries.iter().map(|e| e.entry.entry_id())).unwrap();
        submitted.access_work.entries_root = root;
        submitted.access_work.entries_count = count as u16;
        loop {
            submitted.access_work.output_hash = submitted.access_work.recompute_output_hash();
            if AdmissionWork::from_be_bytes(submitted.access_work.output_hash.0)
                <= submitted.access_work.target
            {
                break;
            }
            submitted.access_work.nonce += 1;
        }
        submitted.header.entries_root = root;
        submitted.header.entries_count = count as u16;
        submitted.header.access_work_id = submitted.access_work.work_id();
        submitted.header.cumulative_work = cumulative
            .checked_add(submitted.access_work.header_work())
            .unwrap();
        parent = submitted.header.header_id();
        cumulative = submitted.header.cumulative_work;
        sources.push(submitted);
    }
    let mut proof = AdmissionCheckpointProofV1 {
        context: genesis.context.clone(),
        prior_committed_header: genesis.genesis_header,
        prior_checkpoint_accumulator: replay
            .ledger
            .admission_state
            .as_ref()
            .unwrap()
            .checkpoint_accumulator,
        batch_segment: sources[..512]
            .iter()
            .map(|s| AdmissionCheckpointBatchProofV1 {
                entries: s.entries.iter().map(|e| e.entry.clone()).collect(),
                access_work: s.access_work.clone(),
                header: s.header.clone(),
                ledger_anchor: s.ledger_anchor.clone(),
            })
            .collect(),
        confirmation_segment: Vec::new(),
    };
    let mut used = 512usize;
    for s in &sources[512..] {
        proof
            .confirmation_segment
            .push(AdmissionCheckpointConfirmationProofV1 {
                access_work: s.access_work.clone(),
                header: s.header.clone(),
                ledger_anchor: s.ledger_anchor.clone(),
            });
        if proof.canonical_bytes().is_err() {
            proof.confirmation_segment.pop();
            break;
        }
        used += 1;
    }
    assert!(proof.confirmation_segment.len() >= 32);
    sources.truncate(used);
    let bytes = proof.canonical_bytes().unwrap();
    assert!(
        bytes.len() > 600 * 1024 && bytes.len() <= MAX_ADMISSION_CHECKPOINT_PROOF_WIRE_BYTES,
        "{}",
        bytes.len()
    );
    for s in &sources {
        replay.append_admission_source(s).unwrap();
    }
    let proposal = signed_proposal(
        &replay,
        ConsensusCommand::CommitAdmissionCheckpoint(Box::new(proof)),
    );
    let reference = AdmissionProposalReferenceV1::from_proposal(&proposal).unwrap();
    let resolved = reference.resolve(&bytes).unwrap();
    replay.check_signed_proposal(&resolved).unwrap();
    let proposal_bytes = serde_json::to_vec(&proposal).unwrap();
    let reference_bytes = serde_json::to_vec(&reference).unwrap();
    assert!(proposal_bytes.len() > 600 * 1024 && reference_bytes.len() <= 4096);
    if let Some(output) = std::env::var_os("RLD_LARGE_STAGED_PROOF_FIXTURE_OUT") {
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("proof.wire"), &bytes).unwrap();
        std::fs::write(output.join("proposal.json"), &proposal_bytes).unwrap();
        std::fs::write(output.join("reference.json"), &reference_bytes).unwrap();
        std::fs::write(
            output.join("heartbeat.json"),
            serde_json::to_vec(&first).unwrap(),
        )
        .unwrap();
        for (i, s) in sources.iter().enumerate() {
            std::fs::write(
                output.join(format!("source-{i:04}.frame")),
                super::source_frame::encode_source_frame(s).unwrap(),
            )
            .unwrap();
        }
        std::fs::write(output.join("expected.json"),serde_json::to_vec_pretty(&serde_json::json!({
            "manifest_sha256":PIN,"proof_bytes":bytes.len(),"proposal_json_bytes":proposal_bytes.len(),"reference_json_bytes":reference_bytes.len(),
            "source_headers":sources.len(),"batch_headers":512,"batch_entries":512,"confirmation_headers":sources.len()-512,
            "proof_id":reference.proof_id,"expected_height":proposal.expected_height,"expected_state_root":proposal.expected_state_root,
            "public_fixture_keys_only":true,"signature_authorized":false,
        })).unwrap()).unwrap();
    }
}

#[test]
fn obligation_capture_fast_path_matches_full_projection_and_checks_retained_sources() {
    let mut replay = M0CandidateReplay::from_pinned_genesis(GENESIS, PIN).unwrap();
    for frame in observation_fixture() {
        let previous = replay.admission_obligations.clone();
        frame.replay(&mut replay).unwrap();
        let full = previous.with_full_current_observation(&replay).unwrap();
        assert_eq!(replay.admission_obligations, full);
    }
    // A known selected entry must not suppress missing/corrupt availability.
    let (mut replay, _) = observed_fixture();
    let history = replay.admission_obligations.clone();
    let observation = replay.observe_admission().unwrap();
    let first_header = observation.source_headers[0];
    let entry = replay
        .log
        .retained_header_batch(first_header)
        .unwrap()
        .entries[0]
        .clone();
    assert_eq!(history.with_current_observation(&replay).unwrap(), history);
    let payload = replay.sidecars.remove(&entry.payload_commitment).unwrap();
    assert!(history.with_current_observation(&replay).is_err());
    assert!(history.with_full_current_observation(&replay).is_err());
    replay
        .sidecars
        .insert(entry.payload_commitment, Arc::new(vec![0]));
    assert!(history.with_current_observation(&replay).is_err());
    replay.sidecars.insert(entry.payload_commitment, payload);
    let anchor_height = replay
        .log
        .retained_header_batch(first_header)
        .unwrap()
        .ledger_anchor
        .height;
    let anchor = replay.anchors.remove(&anchor_height).unwrap();
    assert!(history.with_current_observation(&replay).is_err());
    replay.anchors.insert(anchor_height, anchor);
    assert_eq!(history.with_current_observation(&replay).unwrap(), history);
}

#[test]
fn reserved_upgrade_schedule_inspection_binds_authenticated_parent_and_wire() {
    use crate::genesis::upgrade_wire::ScheduleUpgradeV1;
    let bytes = include_bytes!("../../../../vectors/m0-genesis-v3/manifest.json");
    let manifest: crate::SignedM0GenesisManifestV3 = serde_json::from_slice(bytes).unwrap();
    let replay = M0CandidateReplay::from_pinned_genesis(bytes, &manifest.manifest_sha256).unwrap();
    let parent = replay.ledger();
    let birth = parent.m0_network_birth_v3.as_ref().unwrap();
    let active = parent.m0_active_protocol.as_ref().unwrap();
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../vectors/upgrade-command-v1/vectors.json"
    ))
    .unwrap();
    let mut schedule: ScheduleUpgradeV1 =
        serde_json::from_value(corpus["positive"][0]["value"].clone()).unwrap();
    schedule.network_domain = parent.descriptor.network_domain.clone();
    schedule.zone_id = parent.descriptor.zone_id.clone();
    schedule.currency_genesis =
        crate::AdmissionHash32::from_hex(&parent.descriptor.currency_genesis_root).unwrap();
    schedule.protocol_era = u128::from(parent.descriptor.protocol_era);
    schedule.crypto_era = u128::from(parent.descriptor.crypto_era);
    schedule.prior_active_commitment =
        crate::AdmissionHash32::from_hex(&crate::hash_bytes(&active.canonical_bytes().unwrap()))
            .unwrap();
    schedule.immutable_invariant_commitment =
        crate::AdmissionHash32::from_hex(&crate::hash_bytes(&birth.canonical_bytes().unwrap()))
            .unwrap();
    schedule.activation_height = u128::from(parent.height)
        + 1
        + 2 * birth
            .admission_genesis
            .config
            .contribution_epoch_mapping
            .ledger_blocks_per_contribution_epoch;
    schedule.implementation_source_commitment =
        AdmissionHash32::from_hex(crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
            .unwrap();
    let compiled = crate::genesis::upgrade_migration::first_migration_descriptor();
    schedule.migration_id = compiled.migration_id;
    schedule.migration_code_hash =
        AdmissionHash32::from_hex(&compiled.migration_code_hash).unwrap();
    schedule.specification_hash = AdmissionHash32::from_hex(&compiled.specification_hash).unwrap();
    schedule.vector_root = AdmissionHash32::from_hex(&compiled.vector_root).unwrap();
    schedule.required_capabilities = compiled.required_capabilities;
    let before = serde_json::to_vec(parent).unwrap();
    let result = serde_json::to_value(replay.inspect_upgrade_schedule(&schedule).unwrap()).unwrap();
    assert_eq!(
        result["command_sha256"],
        crate::hash_bytes(&schedule.candidate_command_bytes().unwrap())
    );
    assert_eq!(result["intent_id"], schedule.intent_id().unwrap());
    assert_eq!(result["parent_state_root"], parent.state_root().unwrap());
    assert_eq!(result["command_tag"], 37);
    for flag in [
        "signature_authorized",
        "migration_verified",
        "schedule_finalized",
    ] {
        assert_eq!(result[flag], false);
    }
    for (key, value) in [
        ("zone_id", serde_json::json!("other-zone")),
        ("network_domain", serde_json::json!("rldcoin:testnet:v1")),
        ("currency_genesis", serde_json::json!("09".repeat(32))),
        ("protocol_era", serde_json::json!("99")),
        ("crypto_era", serde_json::json!("99")),
        (
            "prior_active_commitment",
            serde_json::json!("09".repeat(32)),
        ),
        (
            "immutable_invariant_commitment",
            serde_json::json!("09".repeat(32)),
        ),
        (
            "activation_height",
            serde_json::json!((schedule.activation_height - 1).to_string()),
        ),
    ] {
        let mut altered = serde_json::to_value(&schedule).unwrap();
        altered[key] = value;
        let altered = serde_json::from_value(altered).unwrap();
        assert!(replay.inspect_upgrade_schedule(&altered).is_err(), "{key}");
    }
    let mut unsupported = schedule.clone();
    unsupported.migration_id = "unknown".into();
    let mut unchanged = parent.clone();
    assert!(unchanged
        .execute_consensus_command(ConsensusCommand::ScheduleUpgrade(Box::new(unsupported)))
        .is_err());
    assert_eq!(before, serde_json::to_vec(&unchanged).unwrap());
    let proposal = signed_proposal(
        &replay,
        ConsensusCommand::ScheduleUpgrade(Box::new(schedule.clone())),
    );
    replay
        .check_signed_proposal_for_local_authorization(&proposal)
        .unwrap();
    let mut unsigned = proposal.clone();
    unsigned.signature.clear();
    replay
        .check_unsigned_proposal_for_local_authorization(&unsigned)
        .unwrap();
    let mut false_root = unsigned.clone();
    false_root.expected_state_root = "09".repeat(32);
    assert!(replay
        .check_unsigned_proposal_for_local_authorization(&false_root)
        .is_err());
    let mut false_signature = proposal.clone();
    false_signature.signature = "00".repeat(64);
    assert!(replay
        .check_signed_proposal_for_local_authorization(&false_signature)
        .is_err());
    let commit = certificate(proposal);
    let mut certified = replay.clone();
    let mut insufficient = commit.clone();
    insufficient.votes.truncate(1);
    assert!(certified.replay_candidate_commit(&insufficient).is_err());
    assert_eq!(before, serde_json::to_vec(certified.ledger()).unwrap());
    certified.replay_candidate_commit(&commit).unwrap();
    assert_eq!(
        certified
            .ledger()
            .m0_pending_upgrade
            .as_ref()
            .unwrap()
            .schedule,
        schedule
    );
    let certified_bytes = serde_json::to_vec(certified.ledger()).unwrap();
    if let Some(directory) = std::env::var_os("RLD_UPGRADE_SCHEDULE_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        assert!(
            directory.is_absolute(),
            "evidence output must be outside the crate source tree at an explicit absolute path"
        );
        std::fs::create_dir_all(&directory).unwrap();
        let frame = ReplayFrame::new(ReplayEvent::CertifiedCommit(Box::new(commit.clone())));
        let mut line = serde_json::to_vec(&frame).unwrap();
        line.push(b'\n');
        std::fs::write(directory.join("history.jsonl"), line).unwrap();
        std::fs::write(directory.join("expected.json"), serde_json::to_vec_pretty(&serde_json::json!({
            "manifest_sha256": manifest.manifest_sha256,
            "height": certified.ledger().height.to_string(),
            "state_root": certified.ledger().state_root().unwrap(),
            "implementation_source_commitment": crate::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
            "scope": "DISPOSABLE_TEST_COMMIT_NOT_LIVE_WAL"
        })).unwrap()).unwrap();
    }

    certified.replay_candidate_commit(&commit).unwrap();
    // Exact certified repeats are idempotent; a different signed successor is not.
    let mut conflict = commit.proposal.clone();
    conflict.expected_state_root = "09".repeat(32);
    resign(&mut conflict);
    assert!(certified
        .replay_candidate_commit(&certificate(conflict))
        .is_err());
    assert_eq!(
        certified_bytes,
        serde_json::to_vec(certified.ledger()).unwrap()
    );
    let mut replayed = replay.clone();
    replayed.replay_candidate_commit(&commit).unwrap();
    assert_eq!(
        certified_bytes,
        serde_json::to_vec(replayed.ledger()).unwrap()
    );
    let mut preview = parent.preview_upgrade_schedule(&schedule).unwrap();

    assert_ne!(preview.state_root().unwrap(), parent.state_root().unwrap());
    assert_eq!(preview.height, parent.height + 1);
    assert_eq!(
        result["proposed_schedule_state_root"],
        preview.state_root().unwrap()
    );
    let mut normalized = serde_json::to_value(&preview).unwrap();
    normalized
        .as_object_mut()
        .unwrap()
        .remove("m0_pending_upgrade");
    normalized["height"] = serde_json::json!(parent.height);
    assert_eq!(normalized, serde_json::to_value(parent).unwrap());
    assert!(preview.preview_upgrade_schedule(&schedule).is_err());
    // Well-formed codec fixture is sufficient for plan creation; this test
    // does not claim it is a semantically valid checkpoint for this parent.
    let proof_vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../vectors/admission-checkpoint-proof-v1/vectors.json"
    ))
    .unwrap();
    let proof = AdmissionCheckpointProofV1::from_canonical_bytes(
        &hex::decode(
            proof_vectors["payload"]["canonical_proof_wire_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(preview.plan_admission_checkpoint_proposal(&proof).is_ok());
    let activation = crate::genesis::upgrade_wire::ActivateUpgradeV1 {
        format_version: crate::genesis::upgrade_wire::ACTIVATE_VERSION.into(),
        network_domain: schedule.network_domain.clone(),
        zone_id: schedule.zone_id.clone(),
        currency_genesis: schedule.currency_genesis,
        protocol_era: schedule.protocol_era,
        crypto_era: schedule.crypto_era,
        sequence: schedule.sequence,
        activation_height: schedule.activation_height,
        intent_id: AdmissionHash32::from_hex(&schedule.intent_id().unwrap()).unwrap(),
    };
    assert!(parent
        .inspect_upgrade_activation_for_current_build(&activation)
        .is_err());
    assert!(preview
        .inspect_upgrade_activation_for_current_build(&activation)
        .unwrap_err()
        .contains("exact next scheduled height"));
    let pending_root = preview.state_root().unwrap();
    let persisted = serde_json::to_vec(&preview).unwrap();
    preview = serde_json::from_slice::<crate::Ledger>(&persisted).unwrap();
    assert_eq!(pending_root, preview.state_root().unwrap());
    preview
        .audit_proof_bundle()
        .unwrap()
        .verify_structure()
        .unwrap();
    let mut tampered = preview.clone();
    tampered
        .m0_pending_upgrade
        .as_mut()
        .unwrap()
        .schedule
        .zone_id = "foreign".into();
    assert!(tampered.state_root().is_err());
    let mut changed_root = preview.clone();
    changed_root
        .m0_pending_upgrade
        .as_mut()
        .unwrap()
        .scheduled_parent_root = crate::AdmissionHash32([9; 32]);
    // Structural checks do not authenticate ancestry, but any change is rooted.
    assert_ne!(pending_root, changed_root.state_root().unwrap());
    let mut unreachable = schedule.clone();
    unreachable.activation_height = u128::from(u64::MAX) + 1;
    assert!(parent.preview_upgrade_schedule(&unreachable).is_err());
    while u128::from(preview.height) + 1 < schedule.activation_height {
        preview
            .network_heartbeat(crate::NetworkHeartbeatV1 {
                heartbeat_id: format!("pending-test-{}", preview.height),
                zone_id: preview.descriptor.zone_id.clone(),
                currency_genesis_root: preview.descriptor.currency_genesis_root.clone(),
                protocol_era: preview.descriptor.protocol_era,
                crypto_era: preview.descriptor.crypto_era,
                parent_height: preview.height,
                note_hash: "09".repeat(32),
            })
            .unwrap();
    }
    let mut signing_replay = certified.clone();
    while u128::from(signing_replay.ledger().height) + 1 < schedule.activation_height {
        let commit = heartbeat(&signing_replay);
        signing_replay.replay_candidate_commit(&commit).unwrap();
    }
    let activation_proposal = signed_proposal(
        &signing_replay,
        ConsensusCommand::ActivateUpgrade(Box::new(activation.clone())),
    );
    let signing_parent = serde_json::to_vec(signing_replay.ledger()).unwrap();
    signing_replay
        .check_signed_proposal_for_local_authorization(&activation_proposal)
        .unwrap();
    let mut unsigned_activation = activation_proposal.clone();
    unsigned_activation.signature.clear();
    signing_replay
        .check_unsigned_proposal_for_local_authorization(&unsigned_activation)
        .unwrap();
    unsigned_activation.expected_state_root = "09".repeat(32);
    assert!(signing_replay
        .check_unsigned_proposal_for_local_authorization(&unsigned_activation)
        .is_err());
    let mut invalid_signature = activation_proposal.clone();
    invalid_signature.signature = "00".repeat(64);
    assert!(signing_replay
        .check_signed_proposal_for_local_authorization(&invalid_signature)
        .is_err());
    assert_eq!(
        serde_json::to_vec(signing_replay.ledger()).unwrap(),
        signing_parent
    );
    let boundary = serde_json::to_vec(&preview).unwrap();
    let migrated = preview
        .preview_first_upgrade_activation(&activation)
        .unwrap();
    assert_eq!(migrated.height, preview.height + 1);
    assert!(migrated.m0_pending_upgrade.is_none());
    assert_eq!(
        migrated
            .m0_active_protocol
            .as_ref()
            .unwrap()
            .upgrade_sequence,
        1
    );
    assert_eq!(
        migrated
            .m0_active_protocol
            .as_ref()
            .unwrap()
            .consensus_profile,
        crate::M0_ADMISSION_CONSENSUS_PROFILE
    );
    assert_ne!(
        migrated.state_root().unwrap(),
        preview.state_root().unwrap()
    );
    assert_eq!(migrated.m0_network_birth_v3, preview.m0_network_birth_v3);
    migrated.assert_conservation().unwrap();
    assert!(manifest
        .validate_ledger_identity(&migrated)
        .unwrap_err()
        .contains("runtime admission remains closed"));
    migrated
        .audit_proof_bundle()
        .unwrap()
        .verify_structure()
        .unwrap();
    let recovered: Ledger =
        serde_json::from_slice(&serde_json::to_vec(&migrated).unwrap()).unwrap();
    assert_eq!(
        recovered.state_root().unwrap(),
        migrated.state_root().unwrap()
    );
    assert!(recovered
        .preview_first_upgrade_activation(&activation)
        .is_err());
    let mut continued = recovered.clone();
    continued
        .network_heartbeat(NetworkHeartbeatV1 {
            heartbeat_id: "post-candidate-migration".into(),
            zone_id: continued.descriptor.zone_id.clone(),
            currency_genesis_root: continued.descriptor.currency_genesis_root.clone(),
            protocol_era: continued.descriptor.protocol_era,
            crypto_era: continued.descriptor.crypto_era,
            parent_height: continued.height,
            note_hash: "09".repeat(32),
        })
        .unwrap();
    assert_eq!(continued.height, recovered.height + 1);
    continued.assert_conservation().unwrap();
    for (key, value) in [
        (
            "format_version",
            serde_json::json!("RLD-M0-ACTIVE-PROTOCOL-V1"),
        ),
        ("upgrade_sequence", serde_json::json!("2")),
        ("consensus_profile", serde_json::json!("ANY_COMMAND")),
        ("founder_special_slot_ceiling", serde_json::json!(999)),
        (
            "prior_active_commitment",
            serde_json::json!("09".repeat(32)),
        ),
        ("last_activated_upgrade", serde_json::json!("00".repeat(32))),
    ] {
        let mut active =
            serde_json::to_value(migrated.m0_active_protocol.as_ref().unwrap()).unwrap();
        active[key] = value;
        let active: M0ActiveProtocolStateV1 = serde_json::from_value(active).unwrap();
        assert!(
            active
                .validate_for_birth(migrated.m0_network_birth_v3.as_ref().unwrap())
                .is_err(),
            "{key}"
        );
    }

    for key in [
        "migration_id",
        "migration_code_hash",
        "specification_hash",
        "vector_root",
        "required_capabilities",
    ] {
        let mut bad = preview.clone();
        let mut object =
            serde_json::to_value(&bad.m0_pending_upgrade.as_ref().unwrap().schedule).unwrap();
        object[key] = match key {
            "migration_id" => serde_json::json!("unknown"),
            "required_capabilities" => serde_json::json!(["unknown"]),
            _ => serde_json::json!("09".repeat(32)),
        };
        bad.m0_pending_upgrade.as_mut().unwrap().schedule = serde_json::from_value(object).unwrap();
        let mut request = activation.clone();
        request.intent_id = AdmissionHash32::from_hex(
            &bad.m0_pending_upgrade
                .as_ref()
                .unwrap()
                .schedule
                .intent_id()
                .unwrap(),
        )
        .unwrap();
        assert!(
            bad.preview_first_upgrade_activation(&request)
                .unwrap_err()
                .contains("exact compiled"),
            "{key}"
        );
    }
    assert_eq!(boundary, serde_json::to_vec(&preview).unwrap());
    let preflight = serde_json::to_value(
        preview
            .inspect_upgrade_activation_for_current_build(&activation)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        preflight["parent_state_root"],
        preview.state_root().unwrap()
    );
    assert_eq!(
        preflight["command_sha256"],
        hash_bytes(&activation.candidate_command_bytes().unwrap())
    );
    assert_eq!(preflight["intent_id"], schedule.intent_id().unwrap());
    for flag in [
        "migration_verified",
        "schedule_finality_verified",
        "signature_authorized",
    ] {
        assert_eq!(preflight[flag], false);
    }
    for (key, value) in [
        ("network_domain", serde_json::json!("rldcoin:testnet:v1")),
        ("zone_id", serde_json::json!("other")),
        ("currency_genesis", serde_json::json!("09".repeat(32))),
        ("protocol_era", serde_json::json!("99")),
        ("crypto_era", serde_json::json!("99")),
        ("sequence", serde_json::json!("2")),
        (
            "activation_height",
            serde_json::json!((activation.activation_height + 1).to_string()),
        ),
        ("intent_id", serde_json::json!("09".repeat(32))),
    ] {
        let mut altered = serde_json::to_value(&activation).unwrap();
        altered[key] = value;
        let altered = serde_json::from_value(altered).unwrap();
        assert!(
            preview
                .inspect_upgrade_activation_for_current_build(&altered)
                .is_err(),
            "{key}"
        );
    }
    let mut wrong_build = preview.clone();
    wrong_build
        .m0_pending_upgrade
        .as_mut()
        .unwrap()
        .schedule
        .implementation_source_commitment = AdmissionHash32([9; 32]);
    let mut substituted = activation.clone();
    substituted.intent_id = AdmissionHash32::from_hex(
        &wrong_build
            .m0_pending_upgrade
            .as_ref()
            .unwrap()
            .schedule
            .intent_id()
            .unwrap(),
    )
    .unwrap();
    assert!(wrong_build
        .inspect_upgrade_activation_for_current_build(&substituted)
        .unwrap_err()
        .contains("installed implementation source"));
    assert_eq!(boundary, serde_json::to_vec(&preview).unwrap());

    let heartbeat = crate::NetworkHeartbeatV1 {
        heartbeat_id: "boundary".into(),
        zone_id: preview.descriptor.zone_id.clone(),
        currency_genesis_root: preview.descriptor.currency_genesis_root.clone(),
        protocol_era: preview.descriptor.protocol_era,
        crypto_era: preview.descriptor.crypto_era,
        parent_height: preview.height,
        note_hash: "09".repeat(32),
    };
    assert!(preview
        .plan_admission_checkpoint_proposal(&proof)
        .unwrap_err()
        .to_string()
        .contains("scheduled activation required"));
    let command = ConsensusCommand::NetworkHeartbeat(heartbeat.clone());
    let mut boundary_proposal = ConsensusProposal {
        proposal_id: "pending-boundary-proposal".into(),
        zone_id: preview.descriptor.zone_id.clone(),
        currency_genesis_root: preview.descriptor.currency_genesis_root.clone(),
        protocol_era: preview.descriptor.protocol_era,
        crypto_era: preview.descriptor.crypto_era,
        parent_height: preview.height,
        parent_state_root: preview.state_root().unwrap(),
        round: 0,
        proposer_public_key: deterministic_round_zero_leader(
            &preview.descriptor.validator_keys,
            preview.height,
        )
        .unwrap(),
        command_hash: command
            .wire_v1_command_hash(&preview.descriptor.network_domain)
            .unwrap(),
        command,
        expected_height: preview.height + 1,
        expected_state_root: "09".repeat(32),
        signature: String::new(),
    };
    let earlier = parent.preview_upgrade_schedule(&schedule).unwrap();
    let mut earlier_proposal = boundary_proposal.clone();
    earlier_proposal.parent_height = earlier.height;
    earlier_proposal.parent_state_root = earlier.state_root().unwrap();
    earlier_proposal.proposer_public_key =
        deterministic_round_zero_leader(&earlier.descriptor.validator_keys, earlier.height)
            .unwrap();
    earlier_proposal.expected_height = earlier.height + 1;
    let mut earlier_heartbeat = heartbeat.clone();
    earlier_heartbeat.parent_height = earlier.height;
    let mut earlier_successor = earlier.clone();
    earlier_successor
        .network_heartbeat(earlier_heartbeat.clone())
        .unwrap();
    earlier_proposal.command = ConsensusCommand::NetworkHeartbeat(earlier_heartbeat);
    earlier_proposal.command_hash = earlier_proposal
        .command
        .wire_v1_command_hash(&earlier.descriptor.network_domain)
        .unwrap();
    earlier_proposal.expected_state_root = earlier_successor.state_root().unwrap();
    resign(&mut earlier_proposal);
    earlier
        .validate_consensus_proposal(&earlier_proposal)
        .unwrap();
    resign(&mut boundary_proposal);
    boundary_proposal
        .verify_wire_v1(&preview.descriptor.network_domain)
        .unwrap();
    assert!(preview
        .validate_consensus_proposal_authority_and_prestate(&boundary_proposal)
        .unwrap_err()
        .to_string()
        .contains("scheduled activation required"));
    assert!(preview
        .lock_consensus_vote(&boundary_proposal)
        .unwrap_err()
        .to_string()
        .contains("scheduled activation required"));
    assert!(preview.network_heartbeat(heartbeat.clone()).is_err());
    assert_eq!(boundary, serde_json::to_vec(&preview).unwrap());
    let mut restored: crate::Ledger = serde_json::from_slice(&boundary).unwrap();
    assert_eq!(
        preflight,
        serde_json::to_value(
            restored
                .inspect_upgrade_activation_for_current_build(&activation)
                .unwrap()
        )
        .unwrap()
    );

    assert!(restored.plan_admission_checkpoint_proposal(&proof).is_err());
    assert!(restored
        .validate_consensus_proposal_authority_and_prestate(&boundary_proposal)
        .is_err());
    assert!(restored.lock_consensus_vote(&boundary_proposal).is_err());
    assert!(restored.network_heartbeat(heartbeat).is_err());
    assert_eq!(boundary, serde_json::to_vec(&restored).unwrap());
    assert_eq!(before, serde_json::to_vec(replay.ledger()).unwrap());
}
